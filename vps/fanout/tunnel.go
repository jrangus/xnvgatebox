package main

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// SocksCred 是一条隧道的 SOCKS5 访问凭据。
//
// 每条隧道一套独立凭据：泄露一条不会连累其他出口，
// 换节点时也能只重置这一条而不影响已分发的其他配置。
type SocksCred struct {
	User string `json:"user"`
	Pass string `json:"pass"`
}

// Tunnel 是一条运行中的隧道：一个 netns + 一个 openvpn 进程 + 一个本地 SOCKS5 端口。
type Tunnel struct {
	Slot           int         `json:"slot"`
	Port           int         `json:"port"`
	Node           Node        `json:"node"`
	Status         string      `json:"status"` // starting | up | failed | stopped
	ExitIP         string      `json:"exit_ip"`
	Err            string      `json:"err,omitempty"`
	Since          time.Time   `json:"since"`
	Cred           SocksCred   `json:"cred"`
	Policy         *SlotPolicy `json:"policy,omitempty"`
	previousPolicy *SlotPolicy
	LatencyMS      float64 `json:"latency_ms,omitempty"`
	// Transport is openvpn for the original xnvgatebox slots and sstp for a
	// VPS-hosted SSTP exit promoted from the verified resource page.
	Transport      string `json:"transport,omitempty"`
	SSTPPort       int    `json:"sstp_port,omitempty"`
	SourceCategory string `json:"source_category,omitempty"`
	SourceName     string `json:"source_name,omitempty"`
	Native         bool   `json:"native,omitempty"`

	ns                  string
	listener            net.Listener
	ovpn                *exec.Cmd
	sstpDir             string
	mu                  sync.Mutex
	opMu                sync.Mutex
	changeMu            sync.Mutex
	workCtx             context.Context
	cancelWork          context.CancelFunc
	clients             map[net.Conn]bool
	cooldown            map[string]time.Time
	validating          bool // permits only the manager's own expected/actual probe
	validationCred      *SocksCred
	onProbePhase        func(string)
	probeStage          string
	networkIndex        *int
	egress              *EgressProfile
	egressExpectedIP    string
	egressActualIP      string
	egressVerifiedAt    string
	egressNodeHost      string
	egressProfileDigest string
	// swapped 是这条出口换节点时用过的 hostname，按时间先后排。
	// 手动换节点要避开它们：只排除"当前这个"的话，连点两次就会在
	// 两个节点之间来回跳（A 换成 B，B 再换回 A）。
	swapped []string
	// prevHost 是"换节点动作还没收尾"的标记：记着换之前绑的是谁。
	//
	// 换节点分两步——先把隧道连到新节点，再把入站从旧节点改绑过来。
	// 两步之间崩溃或重启的话，存盘的隧道已经是新节点、而入站还指着旧节点，
	// 两边对不上，那个入站就掉成了没人认领的孤儿。
	// 这个字段跟着状态一起落盘，重启后照着它把入站接回来。
	prevHost string
}

const (
	tunnelTransportOpenVPN = "openvpn"
	tunnelTransportSSTP    = "sstp"
)

func (t *Tunnel) transport() string {
	if t.Transport == tunnelTransportSSTP {
		return tunnelTransportSSTP
	}
	return tunnelTransportOpenVPN
}

func (t *Tunnel) sourceCategory() string {
	if t.SourceCategory == exitSourceHome || t.SourceCategory == exitSourceNativeDC {
		return t.SourceCategory
	}
	return exitSourceStable
}

// prevHostOf 读"换节点未收尾"标记。
func (t *Tunnel) prevHostOf() string {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.prevHost
}

// setPrevHost 记下或清掉"换节点未收尾"标记。空串表示已经收尾。
func (t *Tunnel) setPrevHost(host string) {
	t.mu.Lock()
	t.prevHost = host
	t.mu.Unlock()
}

// swapHistoryMax 是换节点历史的上限。
//
// 留太多会把同地区的候选节点排干，反而让自动重连没得选；
// 留太少又挡不住来回跳。一个地区的可用节点通常个位数到十几个，
// 16 条足够覆盖"一轮都换过"的情况。
const swapHistoryMax = 16

// swapAvoid 返回换节点时要跳过的 hostname：历史用过的，加上当前这个。
func (t *Tunnel) swapAvoid() map[string]bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	out := make(map[string]bool, len(t.swapped)+1)
	for _, h := range t.swapped {
		out[h] = true
	}
	if t.Node.HostName != "" {
		out[t.Node.HostName] = true
	}
	return out
}

// rememberSwap 把一个换掉的节点记进历史，超出上限就丢最早的。
func (t *Tunnel) rememberSwap(host string) {
	if host == "" {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	for _, h := range t.swapped {
		if h == host {
			return
		}
	}
	t.swapped = append(t.swapped, host)
	if len(t.swapped) > swapHistoryMax {
		t.swapped = t.swapped[len(t.swapped)-swapHistoryMax:]
	}
}

// forgetSwaps 清空换节点历史。同地区的节点都换过一轮之后要清一次，
// 否则用户再点就只能收到"没有可用节点"。
func (t *Tunnel) forgetSwaps() {
	t.mu.Lock()
	t.swapped = nil
	t.mu.Unlock()
}

// 名字里都带上实例标识，否则同机第二个 fanout 会把这条隧道拆掉（见 instance.go）。
// 默认工作目录下 instTag 是空串、instBase 是 99，名字与老版本完全一致。
func (t *Tunnel) nsName() string { return fmt.Sprintf("fo%s%d", instTag, t.Slot) }

// vethNames 返回母机侧与 netns 侧的网卡名。
// 网卡名上限 15 个字符，"fov" + 4 位标识 + 槽位最多 9 个，留足余量。
func (t *Tunnel) vethNames() (string, string) {
	return fmt.Sprintf("fov%s%d", instTag, t.Slot), fmt.Sprintf("fop%s%d", instTag, t.Slot)
}

// run 执行一条网络配置命令。
//
// 走 cmdCombined 而不是直接 exec：建 veth、改 iptables 都是"在当前网络
// 命名空间里生效"的操作，线程可能已经被 dialerInNetns 带进某条隧道，
// 那样规则会加到隧道内部，母机上什么也没有（见 netnsguard.go）。
func run(name string, args ...string) error {
	out, err := cmdCombined(exec.Command(name, args...))
	if err != nil {
		return fmt.Errorf("%s %s: %v: %s", name, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

// runQuiet 执行清理类命令，忽略"本来就不存在"这类错误。
func runQuiet(name string, args ...string) {
	_ = cmdRun(exec.Command(name, args...))
}

// setupNetns 建立 netns 与 veth 链路，并配好 NAT 与转发放行。
func (t *Tunnel) setupNetns() error {
	if t.linkIndex() < 0 || t.linkIndex() >= networkLinkCount {
		return fmt.Errorf("网络地址分配无效")
	}
	ns := t.nsName()
	veth, peer := t.vethNames()

	t.teardownNetns()

	if err := run("ip", "netns", "add", ns); err != nil {
		return err
	}
	if err := run("ip", "netns", "exec", ns, "ip", "link", "set", "lo", "up"); err != nil {
		return err
	}
	if err := run("ip", "link", "add", veth, "type", "veth", "peer", "name", peer); err != nil {
		return err
	}
	if err := run("ip", "link", "set", peer, "netns", ns); err != nil {
		return err
	}
	if err := run("ip", "addr", "add", t.linkAddress(1)+"/30", "dev", veth); err != nil {
		return err
	}
	if err := run("ip", "link", "set", veth, "up"); err != nil {
		return err
	}
	if err := run("ip", "netns", "exec", ns, "ip", "addr", "add", t.linkAddress(2)+"/30", "dev", peer); err != nil {
		return err
	}
	if err := run("ip", "netns", "exec", ns, "ip", "link", "set", peer, "up"); err != nil {
		return err
	}
	if err := run("ip", "netns", "exec", ns, "ip", "route", "add", "default", "via", t.linkAddress(1)); err != nil {
		return err
	}

	// netns 内的 DNS，仅用于 openvpn 解析远端主机名
	nsDir := filepath.Join("/etc/netns", ns)
	if err := os.MkdirAll(nsDir, 0755); err != nil {
		return fmt.Errorf("创建 %s 失败: %w", nsDir, err)
	}
	if err := os.WriteFile(filepath.Join(nsDir, "resolv.conf"), []byte("nameserver 8.8.8.8\n"), 0644); err != nil {
		return fmt.Errorf("写 resolv.conf 失败: %w", err)
	}

	cidr := t.linkCIDR()
	ensureRule("nat", "POSTROUTING", "-s", cidr, "-j", "MASQUERADE")
	if err := installKillSwitch(t); err != nil {
		return err
	}
	return nil
}

// ensureRule 幂等追加一条 iptables 规则。
func ensureRule(table, chain string, spec ...string) {
	check := append([]string{"-w", "5", "-t", table, "-C", chain}, spec...)
	if cmdRun(exec.Command("iptables", check...)) == nil {
		return
	}
	add := append([]string{"-w", "5", "-t", table, "-A", chain}, spec...)
	runQuiet("iptables", add...)
}

// ensureRuleInsert 幂等插入规则到链首。
// FORWARD 链末尾常有兜底 REJECT，必须插到最前面才生效。
func ensureRuleInsert(table, chain string, spec ...string) {
	check := append([]string{"-w", "5", "-t", table, "-C", chain}, spec...)
	if cmdRun(exec.Command("iptables", check...)) == nil {
		return
	}
	ins := append([]string{"-w", "5", "-t", table, "-I", chain, "1"}, spec...)
	runQuiet("iptables", ins...)
}

func (t *Tunnel) teardownNetns() {
	t.clearEgress()
	ns := t.nsName()
	cidr := t.linkCIDR()
	veth, _ := t.vethNames()
	// Candidate rotation can reach teardown after OpenVPN has failed before
	// startOpenVPN returned. Kill that process here as well; otherwise the
	// next candidate inherits the same tun name and stale OpenVPN children
	// remain outside the manager's state.
	if t.ovpn != nil && t.ovpn.Process != nil {
		_ = t.ovpn.Process.Kill()
		t.ovpn = nil
	}
	if t.sstpDir != "" {
		_ = os.RemoveAll(t.sstpDir)
		t.sstpDir = ""
	}
	removeKillSwitch(t)
	runQuiet("ip", "netns", "del", ns)
	runQuiet("ip", "link", "del", veth)
	runQuiet("iptables", "-w", "5", "-t", "nat", "-D", "POSTROUTING", "-s", cidr, "-j", "MASQUERADE")
}

// startOpenVPN 在 netns 内拉起 openvpn，并等待 tun0 拿到地址。
func (t *Tunnel) startOpenVPN(dir string) error {
	ns := t.nsName()
	cfgPath := filepath.Join(dir, ns+".ovpn")
	if err := os.WriteFile(cfgPath, []byte(t.Node.Config), 0600); err != nil {
		return fmt.Errorf("写配置失败: %w", err)
	}
	authPath := filepath.Join(dir, "auth.txt")
	if err := os.WriteFile(authPath, []byte("vpn\nvpn\n"), 0600); err != nil {
		return fmt.Errorf("写凭据失败: %w", err)
	}

	logPath := filepath.Join(dir, ns+".log")
	ctx := t.workContext()
	cmd := exec.CommandContext(ctx, "ip", "netns", "exec", ns, "openvpn",
		"--config", cfgPath,
		"--auth-user-pass", authPath,
		"--auth-nocache",
		"--dev", "tun0",
		"--connect-retry-max", "2",
		"--connect-timeout", "20",
		"--tls-timeout", "10",
		"--data-ciphers", "AES-128-CBC:AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305",
		"--verb", "3",
		"--log", logPath,
	)
	if err := cmdStart(cmd); err != nil {
		return fmt.Errorf("启动 openvpn 失败: %w", err)
	}
	t.ovpn = cmd
	exited := make(chan struct{})
	go func() { _ = cmd.Wait(); close(exited) }()

	// openvpn 建好 tun0 前 SOCKS5 无法正常出网，这里等它就绪
	deadline := time.Now().Add(40 * time.Second)
	for time.Now().Before(deadline) {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if out, err := cmdOutput(exec.CommandContext(ctx, "ip", "netns", "exec", ns, "ip", "-4", "addr", "show", "tun0")); err == nil {
			if strings.Contains(string(out), "inet ") {
				return nil
			}
		}
		select {
		case <-exited:
			return fmt.Errorf("openvpn 提前退出，详见 %s", logPath)
		default:
		}
		if !waitForWork(ctx, time.Second) {
			return ctx.Err()
		}
	}
	return fmt.Errorf("等待 tun0 就绪超时，详见 %s", logPath)
}

// serve 在母机上监听 SOCKS5 端口，出站连接则在 netns 内建立。
// 监听必须留在母机侧：netns 内的 loopback 与母机彼此独立，
// 监听在 netns 里的话外部根本连不上。
func (t *Tunnel) serve() error {
	// 端口要尽量保持不变，否则用户已经分发出去的客户端配置会失效。
	// 进程刚重启时旧监听可能还在 TIME_WAIT，这里给几秒重试窗口。
	var ln net.Listener
	var err error
	for i := 0; i < 6; i++ {
		if err := t.workContext().Err(); err != nil {
			return err
		}
		// SOCKS is an internal hand-off to Xray/3x-ui.  Never expose it on the
		// VPS public interface; the panel's own inbound ports remain separate.
		ln, err = net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", t.Port))
		if err == nil {
			break
		}
		if !waitForWork(t.workContext(), time.Second) {
			return t.workContext().Err()
		}
	}
	if err != nil {
		return fmt.Errorf("Slot 固定端口 %d 监听失败: %w", t.Port, err)
	}
	t.listener = ln
	dial := dialerInNetns(t.nsName())

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			// Keep the stable listener during startup/reconnect, but refuse new
			// business until the current node has passed expected/actual checks.
			// This prevents callers from using a half-built namespace or a slot
			// whose OpenVPN process has just been killed.
			if !t.trackClient(conn) {
				_ = conn.Close()
				continue
			}
			// 每次连接现取凭据：改口令后不必重建监听，新连接立刻按新凭据校验
			cred := t.probeCredential()
			ctx := t.workContext()
			go func() {
				defer t.untrackClient(conn)
				serveSocks(conn, &cred, func(network, addr string) (net.Conn, error) {
					if err := ctx.Err(); err != nil {
						return nil, err
					}
					remote, err := dial(network, addr)
					if err == nil && ctx.Err() != nil {
						remote.Close()
						return nil, ctx.Err()
					}
					return remote, err
				})
			}()
		}
	}()
	return nil
}

// credential 取一份凭据副本，避免读写并发。
func (t *Tunnel) credential() SocksCred {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.Cred
}

func (t *Tunnel) acceptsSocks() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.acceptsSocksLocked()
}

func (t *Tunnel) acceptsSocksLocked() bool {
	if t.workCtx != nil && t.workCtx.Err() != nil {
		return false
	}
	if t.validating {
		return t.validationCred != nil
	}
	if t.Status != "up" {
		return false
	}
	if t.Policy != nil {
		if t.egress == nil || t.Policy.checkImageForProtocol(*t.egress, t.transport()) != nil || t.Policy.checkLatency(t.LatencyMS) != nil {
			return false
		}
	}
	return true
}

func (t *Tunnel) trackClient(conn net.Conn) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	if !t.acceptsSocksLocked() {
		return false
	}
	if t.clients == nil {
		t.clients = map[net.Conn]bool{}
	}
	t.clients[conn] = true
	return true
}

func (t *Tunnel) untrackClient(conn net.Conn) {
	t.mu.Lock()
	delete(t.clients, conn)
	t.mu.Unlock()
}

func (t *Tunnel) setValidating(v bool) {
	t.mu.Lock()
	t.validationCred = nil
	t.validating = false
	if v && (t.workCtx == nil || t.workCtx.Err() == nil) {
		if cred, err := newSocksCred(); err == nil {
			t.validationCred = &cred
			t.validating = true
		}
	}
	t.mu.Unlock()
}

func (t *Tunnel) probeCredential() SocksCred {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.validating && t.validationCred != nil {
		return *t.validationCred
	}
	return t.Cred
}

// setCredential 换掉这条隧道的 SOCKS5 凭据。已建立的连接不受影响，
// 新连接立即按新凭据校验。
func (t *Tunnel) setCredential(c SocksCred) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.Cred = c
}

// probeExitIP 通过隧道查询出口 IP，用于确认这条隧道确实换了 IP。
func (t *Tunnel) probeExitIP() (string, error) {
	return t.probeExpectedExitIP()
}

// stop 停止这条隧道并清理它占用的所有资源。
func (t *Tunnel) stop() {
	t.stopWithCleanup(t.teardownNetns)
}

func (t *Tunnel) stopWithCleanup(cleanup func()) {
	t.blockWork()
	t.opMu.Lock()
	defer t.opMu.Unlock()
	t.mu.Lock()
	t.Status = "stopped"
	t.mu.Unlock()
	if t.listener != nil {
		t.listener.Close()
		t.listener = nil
	}
	if t.ovpn != nil && t.ovpn.Process != nil {
		_ = t.ovpn.Process.Kill()
		t.ovpn = nil
	}
	cleanup()
}
