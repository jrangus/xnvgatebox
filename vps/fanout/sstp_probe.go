package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

func sstpDependencies() error {
	for _, name := range []string{"sstpc", "pppd", "unshare", "mount", "curl", "ip", "iptables"} {
		if _, err := exec.LookPath(name); err != nil {
			return fmt.Errorf("SSTP 本地检测缺少 %s，请通过项目安装入口更新依赖", name)
		}
	}
	return nil
}

func sstpPublicIPv4(text string) bool {
	ip, err := netip.ParseAddr(text)
	if err != nil || !ip.Is4() || !ip.IsGlobalUnicast() || ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
		return false
	}
	for _, cidr := range []string{"0.0.0.0/8", "100.64.0.0/10", "192.0.0.0/24", "192.0.2.0/24", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "240.0.0.0/4"} {
		if netip.MustParsePrefix(cidr).Contains(ip) {
			return false
		}
	}
	return true
}

func officialSstpEndpoint(n Node, e SstpEndpoint) bool {
	host := strings.ToLower(e.Host)
	return e.Host == n.HostName && !strings.ContainsAny(host, "/\\\x00\r\n :") &&
		(strings.HasSuffix(host, ".opengw.net") || strings.HasSuffix(host, ".vpngate.v4.open.ad.jp")) &&
		e.Port > 0 && e.Port <= 65535 && sstpPublicIPv4(n.IP)
}

// Verify both the issuer and hostname before creating PPP or any route. No
// insecure mode is offered; an OpenVPN/TCP candidate is not SSTP evidence.
func verifySstpTLS(ctx context.Context, ip string, e SstpEndpoint) error {
	dialer := &tls.Dialer{NetDialer: &net.Dialer{Timeout: 5 * time.Second}, Config: &tls.Config{ServerName: e.Host, MinVersion: tls.VersionTLS12}}
	timeout, cancel := context.WithTimeout(ctx, 6*time.Second)
	defer cancel()
	conn, err := dialer.DialContext(timeout, "tcp4", net.JoinHostPort(ip, strconv.Itoa(e.Port)))
	if err != nil {
		return err
	}
	return conn.Close()
}

func sstpFailure(ctx context.Context, err error) string {
	if ctx.Err() != nil {
		if ctx.Err() == context.Canceled {
			return "cancelled"
		}
		return "check_timeout"
	}
	if strings.Contains(err.Error(), "certificate") || strings.Contains(err.Error(), "x509") {
		return "sstp_certificate_rejected"
	}
	return "sstp_unreachable"
}

func (s *SstpManager) probeNode(parent context.Context, n Node, settings SstpSettings, progress func(string)) CheckResult {
	r := CheckResult{Host: n.HostName, Status: "failed", IPType: "unknown", Code: "sstp_unreachable"}
	ctx, cancel := context.WithTimeout(parent, time.Duration(settings.TimeoutSeconds)*time.Second)
	defer cancel()
	leaseCtx, cancelLease := context.WithCancelCause(ctx)
	defer cancelLease(nil)
	lease := s.c.m.reserveDiagnostic(n, cancelLease)
	if lease == nil {
		r.Status, r.Code = "deferred", "candidate_in_use"
		s.c.m.mu.RLock()
		full := len(s.c.m.tunnels)+len(s.c.m.diagnostics) >= networkLinkCount
		s.c.m.mu.RUnlock()
		if full {
			r.Status, r.Code = "failed", "network_capacity_exhausted"
		}
		return r
	}
	defer func() {
		if r.Code != "sstp_cleanup_failed" {
			s.c.m.releaseDiagnostic(n.HostName, lease)
		}
	}()
	for _, endpoint := range n.SSTPCandidates {
		if !officialSstpEndpoint(n, endpoint) {
			r.Code = "invalid_sstp_candidate"
			continue
		}
		r.Port = endpoint.Port
		progress("sstp_tls")
		if err := verifySstpTLS(leaseCtx, n.IP, endpoint); err != nil {
			r.Code = sstpFailure(leaseCtx, err)
			if leaseCtx.Err() != nil {
				break
			}
			continue
		}
		r = s.probeEndpoint(leaseCtx, n, endpoint, lease, progress)
		if r.Status == "passed" || r.Code == "sstp_cleanup_failed" || leaseCtx.Err() != nil {
			break
		}
	}
	if context.Cause(leaseCtx) == errDiagnosticPreempted {
		r.Status, r.Code = "deferred", "exit_recovery_priority"
	}
	if parent.Err() != nil {
		r.Status, r.Code = "cancelled", "cancelled"
	}
	return r
}

// The child mount namespace hides all host PPP options/hooks/runtime files.
// Both SSTP and PPP remain in this instance's isolated network namespace.
const sstpLaunch = "#!/bin/sh\nset -eu\ntask_dir=$1\nmount --make-rprivate /\nmount --bind \"$task_dir/ppp\" /etc/ppp\nmount -t tmpfs -o mode=755 tmpfs /run\nmkdir -p /run/sstpc /run/ppp /run/lock\nca=/etc/ssl/certs/ca-certificates.crt\n[ -f \"$ca\" ] || ca=/etc/pki/tls/certs/ca-bundle.crt\n[ -r \"$ca\" ] || exit 1\nexec \"$2\" --ca-cert \"$ca\" --log-stderr --log-level 2 --tls-ext --host \"$3\" --ipparam \"$4\" \"$5\" file \"$task_dir/$4.ppp\"\n"

func writeSstpFiles(dir, ns string) error {
	pppDir := filepath.Join(dir, "ppp")
	if err := os.Mkdir(pppDir, 0700); err != nil {
		return err
	}
	// The official VPN Gate service uses public vpn/vpn credentials. They are
	// kept in a private options file, never in process arguments or reports.
	options := "noauth\nnodetach\nnopersist\nnoipdefault\nipcp-accept-local\nipcp-accept-remote\nnodefaultroute\nnoipv6\nname vpn\npassword vpn\nifname tun0\nlinkname " + ns + "\nipparam " + ns + "\nnobsdcomp\nnodeflate\nnovj\nlcp-echo-interval 3\nlcp-echo-failure 3\n"
	files := map[string]string{filepath.Join(dir, ns+".ppp"): options, filepath.Join(dir, ns+".launch"): sstpLaunch, filepath.Join(pppDir, "options"): "", filepath.Join(dir, ns+".curl"): ""}
	for _, hook := range []string{"ip-pre-up", "ip-up", "ip-down", "auth-up", "auth-down", "ipv6-up", "ipv6-down"} {
		files[filepath.Join(pppDir, hook)] = "#!/bin/sh\nexit 0\n"
	}
	for name, data := range files {
		mode := os.FileMode(0600)
		if filepath.Dir(name) == pppDir && filepath.Base(name) != "options" {
			mode = 0700
		}
		if err := os.WriteFile(name, []byte(data), mode); err != nil {
			return err
		}
	}
	return nil
}

func (s *SstpManager) probeEndpoint(ctx context.Context, n Node, e SstpEndpoint, lease *diagnosticLease, progress func(string)) (r CheckResult) {
	r = CheckResult{Host: n.HostName, Port: e.Port, Status: "failed", IPType: "unknown", Code: "probe_environment_failed"}
	dir, err := os.MkdirTemp(s.c.m.workDir, ".connectivity-sstp-")
	if err != nil {
		return r
	}
	t := &Tunnel{Slot: lease.slot, networkIndex: &lease.networkIndex, Node: n}
	// Pin the server IP, so a DNS change cannot open a private/control-plane route.
	t.Node.Config = fmt.Sprintf("proto tcp\nremote %s %d\n", n.IP, e.Port)
	t.resetWork()
	var cmd *exec.Cmd
	var done chan error
	defer func() {
		progress("cleanup")
		if cmd != nil && cmd.Process != nil {
			// This private process group was created by us; reap its leader before
			// deleting the namespace. Remaining PPP children are verified via pidfd.
			if done != nil {
				_ = cmd.Process.Kill()
			}
			if done != nil {
				<-done
			}
		}
		if err := s.c.cleanupDiagnosticTunnel(t); err != nil {
			r.Status, r.Code = "failed", "sstp_cleanup_failed"
			return
		}
		_ = os.RemoveAll(dir)
	}()
	manifest, _ := json.Marshal(diagnosticResource{Config: t.Node.Config, Slot: t.Slot, NetworkIndex: lease.networkIndex, Node: t.Node})
	if os.WriteFile(filepath.Join(dir, "diagnostic.json"), manifest, 0600) != nil || writeSstpFiles(dir, t.nsName()) != nil {
		return r
	}
	progress("setup")
	if err = t.setupNetns(); err != nil {
		return r
	}
	if err = sstpMatchUnderlayMTU(ctx, t, n.IP); err != nil {
		return r
	}
	sstpc, _ := exec.LookPath("sstpc")
	command := []string{"netns", "exec", t.nsName(), "unshare", "--mount", "--propagation", "private", "--", "/bin/sh", filepath.Join(dir, t.nsName()+".launch"), dir, sstpc, e.Host, t.nsName(), net.JoinHostPort(n.IP, strconv.Itoa(e.Port))}
	cmd = exec.Command("ip", command...)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true, Pdeathsig: syscall.SIGKILL}
	logFile, err := os.OpenFile(filepath.Join(dir, "sstp.log"), os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return r
	}
	defer logFile.Close()
	cmd.Stdout, cmd.Stderr = logFile, logFile
	if err = cmd.Start(); err != nil {
		return r
	}
	done = make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	progress("sstp_connecting")
	for {
		if ctx.Err() != nil {
			r.Code = sstpFailure(ctx, ctx.Err())
			return r
		}
		out, _ := cmdOutput(exec.CommandContext(ctx, "ip", "netns", "exec", t.nsName(), "ip", "-4", "-o", "addr", "show", "dev", "tun0"))
		if strings.Contains(string(out), "inet ") {
			break
		}
		select {
		case <-done:
			done = nil
			r.Code = "sstp_handshake_failed"
			return r
		case <-ctx.Done():
			r.Code = sstpFailure(ctx, ctx.Err())
			return r
		case <-time.After(200 * time.Millisecond):
		}
	}
	_, peer := t.vethNames()
	if run("ip", "netns", "exec", t.nsName(), "ip", "route", "replace", n.IP+"/32", "via", t.linkAddress(1), "dev", peer) != nil {
		return r
	}
	if run("ip", "netns", "exec", t.nsName(), "ip", "route", "replace", "default", "dev", "tun0") != nil {
		return r
	}
	progress("verify_exit")
	commandCurl := func(target string, timing bool) ([]byte, error) {
		args := []string{"netns", "exec", t.nsName(), "curl", "--disable", "--config", filepath.Join(dir, t.nsName()+".curl"), "--proxy", "", "--noproxy", "*", "--interface", "tun0", "-4fsS", "--proto", "=https", "--proto-redir", "=https", "--connect-timeout", "5", "--max-time", "15", "--max-filesize", "65536"}
		if timing {
			args = append(args, "--write-out", "\n%{time_total}")
		}
		cmd := exec.CommandContext(ctx, "ip", append(args, target)...)
		cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
		return cmdOutput(cmd)
	}
	ip, latency, err := probeSocksPair(func(target string) ([]byte, error) { return commandCurl(target, true) })
	if err != nil {
		r.Code = "sstp_https_failed"
		return r
	}
	if !sstpPublicIPv4(ip) || ip == hostPublicIP() {
		r.Code = "exit_ip_mismatch"
		return r
	}
	body, err := commandCurl("https://www.example.com/", false)
	if err != nil || !strings.Contains(string(body), "Example Domain") {
		r.Code = "sstp_content_failed"
		return r
	}
	r.Status, r.Code, r.ActualIP, r.LatencyMS = "passed", "", ip, latency
	return r
}

func lookupSstpEgress(ctx context.Context, dir, ip string) EgressProfile {
	unknown := EgressProfile{IP: ip, Protocol: "sstp", IPType: "unknown", IntelligenceStatus: "not_configured"}
	bounded, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(bounded, "python3", envOr("FANOUT_TOOLBOX_SCRIPT", "/usr/local/lib/xnvgatebox/scripts/toolbox.py"), "--config", envOr("FANOUT_POOL_CONFIG", "/etc/xnvgatebox/pool.json"), "--env-file", envOr("FANOUT_INTELLIGENCE_ENV_FILE", "/etc/xnvgatebox/intelligence.env"), "profile-sstp", "--ip", ip, "--country", "--cache", filepath.Join(dir, "intelligence", "sstp-cache.json"))
	out, err := cmdOutput(cmd)
	if err != nil {
		return unknown
	}
	return decodeMeasuredEgress(out, ip, "sstp")
}

// A veth defaults to 1500 even when the VPS uplink is smaller (for example
// 1400). Advertise an appropriate TCP MSS before SSTP TLS starts, otherwise
// larger TLS records can stall behind the underlay's MTU.
func sstpMatchUnderlayMTU(ctx context.Context, t *Tunnel, ip string) error {
	out, err := cmdOutput(exec.CommandContext(ctx, "ip", "-j", "route", "get", ip))
	if err != nil {
		return err
	}
	var routes []struct {
		Dev string `json:"dev"`
	}
	if json.Unmarshal(out, &routes) != nil || len(routes) == 0 || routes[0].Dev == "" {
		return fmt.Errorf("SSTP route MTU unavailable")
	}
	out, err = cmdOutput(exec.CommandContext(ctx, "ip", "-j", "link", "show", "dev", routes[0].Dev))
	if err != nil {
		return err
	}
	var links []struct {
		MTU int `json:"mtu"`
	}
	if json.Unmarshal(out, &links) != nil || len(links) == 0 || links[0].MTU < 576 {
		return fmt.Errorf("SSTP link MTU unavailable")
	}
	mtu := links[0].MTU
	if mtu > 1400 {
		mtu = 1400
	}
	value := strconv.Itoa(mtu)
	veth, peer := t.vethNames()
	if err := run("ip", "link", "set", "dev", veth, "mtu", value); err != nil {
		return err
	}
	return run("ip", "netns", "exec", t.nsName(), "ip", "link", "set", "dev", peer, "mtu", value)
}
