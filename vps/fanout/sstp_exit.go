package main

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// StartVerifiedSSTP promotes a still-current VPS observation into a normal
// managed Slot. The public SSTP endpoint is never exposed to Xray directly:
// SSTP/PPP stays inside the Slot namespace and the only hand-off is an
// authenticated SOCKS listener on 127.0.0.1.
func (m *Manager) StartVerifiedSSTP(node Node, result CheckResult) (*Tunnel, error) {
	source, native, policy, err := validatedSSTPSource(node, result, time.Now().UTC())
	if err != nil {
		return nil, err
	}

	m.mu.Lock()
	for _, other := range m.tunnels {
		other.mu.Lock()
		occupied := other.Status != "stopped" && other.Node.HostName == node.HostName
		other.mu.Unlock()
		if occupied {
			m.mu.Unlock()
			return nil, fmt.Errorf("该 VPN Gate 服务器已被另一个出口占用")
		}
	}
	slot, err := m.freeSlot()
	if err != nil {
		m.mu.Unlock()
		return nil, err
	}
	taken := map[int]bool{}
	for _, other := range m.tunnels {
		taken[other.Port] = true
	}
	port, fixed, err := fixedSlotPort(slot)
	if err == nil && fixed && (taken[port] || !portAvailable(port)) {
		err = fmt.Errorf("槽位 %d 的固定端口 %d 已被占用", slot, port)
	}
	if err == nil && !fixed {
		port, err = freeRandomPort(taken)
	}
	if err != nil {
		m.mu.Unlock()
		return nil, err
	}
	cred, err := newSocksCred()
	if err != nil {
		m.mu.Unlock()
		return nil, err
	}
	// Pin the observed server IP. The hostname remains available exclusively
	// for certificate verification and cannot redirect the namespace route.
	node.Config = fmt.Sprintf("proto tcp\nremote %s %d\n", node.IP, result.Port)
	t := &Tunnel{
		Slot: slot, Port: port, Node: node, Status: "starting", Since: time.Now(), Cred: cred, Policy: &policy,
		Transport: tunnelTransportSSTP, SSTPPort: result.Port, SourceCategory: source,
		SourceName: "VPN Gate SSTP · VPS 持久出口", Native: native,
	}
	t.resetWork()
	m.tunnels[slot] = t
	delete(m.deletedSlots, slot)
	m.mu.Unlock()
	if err := m.saveState(); err != nil {
		m.mu.Lock()
		delete(m.tunnels, slot)
		m.mu.Unlock()
		t.blockWork()
		return nil, err
	}
	go m.bringUpPersistContext(t, true, true, t.workContext())
	return t, nil
}

func validatedSSTPSource(node Node, result CheckResult, now time.Time) (string, bool, SlotPolicy, error) {
	result = freshSstpResult(node, result, now)
	if result.Status != "passed" || result.Stale || result.Protocol != tunnelTransportSSTP {
		return "", false, SlotPolicy{}, fmt.Errorf("SSTP 实测结果已失效，请重新检测")
	}
	endpointOK := false
	for _, endpoint := range node.SSTPCandidates {
		if endpoint.Port == result.Port && officialSstpEndpoint(node, endpoint) {
			endpointOK = true
			break
		}
	}
	if !endpointOK {
		return "", false, SlotPolicy{}, fmt.Errorf("SSTP 端点已不在当前官方候选中")
	}
	if result.Egress == nil {
		return "", false, SlotPolicy{}, fmt.Errorf("SSTP 连通性已通过，但缺少 IP 类型画像；请配置可信画像服务后重新检测")
	}
	image := *result.Egress
	if image.IntelligenceStatus == "not_configured" {
		return "", false, SlotPolicy{}, fmt.Errorf("SSTP 连通性已通过，但未配置 IP 类型画像服务，无法安全归类为住宅或原生机房")
	}
	if image.IntelligenceStatus != "passed" {
		return "", false, SlotPolicy{}, fmt.Errorf("SSTP 连通性已通过，但 IP 类型画像查询失败；请检查画像服务后重新检测")
	}
	queriedAt, queriedErr := time.Parse(time.RFC3339Nano, image.QueriedAt)
	expiresAt, expiresErr := time.Parse(time.RFC3339Nano, image.ExpiresAt)
	if image.Protocol != tunnelTransportSSTP || image.IP != result.ActualIP ||
		image.Provider == "" || image.RuleVersion == "" ||
		queriedErr != nil || expiresErr != nil || queriedAt.After(now) || !expiresAt.After(queriedAt) || !expiresAt.After(now) {
		return "", false, SlotPolicy{}, fmt.Errorf("SSTP 出口画像不完整")
	}
	actualCountry := verifiedProfileCountry(image)
	source := ""
	native := actualCountry != "" && strings.EqualFold(actualCountry, node.CountryCode)
	switch image.IPType {
	case "strict_residential", "likely_residential":
		source = exitSourceHome
	case "datacenter", "business_isp":
		if !native {
			return "", false, SlotPolicy{}, fmt.Errorf("机房出口的实测国家与来源国家不一致，不能标记为新增原生机房")
		}
		source = exitSourceNativeDC
	default:
		return "", false, SlotPolicy{}, fmt.Errorf("仅允许已验证住宅或原生机房 SSTP 出口，当前类型为 %s", image.IPType)
	}
	policy, err := normalizePolicy(SlotPolicy{Country: actualCountry, AllowedIPTypes: []string{image.IPType}})
	if err != nil {
		return "", false, SlotPolicy{}, err
	}
	return source, native, policy, nil
}

func (t *Tunnel) sstpEndpoint() (SstpEndpoint, error) {
	for _, endpoint := range t.Node.SSTPCandidates {
		if endpoint.Port == t.SSTPPort && officialSstpEndpoint(t.Node, endpoint) {
			return endpoint, nil
		}
	}
	return SstpEndpoint{}, fmt.Errorf("持久 SSTP 端点不再有效")
}

func (t *Tunnel) startSSTP(dir string) error {
	if err := sstpDependencies(); err != nil {
		return err
	}
	endpoint, err := t.sstpEndpoint()
	if err != nil {
		return err
	}
	if err := verifySstpTLS(t.workContext(), t.Node.IP, endpoint); err != nil {
		return fmt.Errorf("SSTP 证书验证失败: %w", err)
	}
	if err := sstpMatchUnderlayMTU(t.workContext(), t, t.Node.IP); err != nil {
		return err
	}
	taskDir := filepath.Join(dir, fmt.Sprintf(".sstp-slot-%d", t.Slot))
	if err := os.RemoveAll(taskDir); err != nil {
		return err
	}
	if err := os.Mkdir(taskDir, 0700); err != nil {
		return err
	}
	t.sstpDir = taskDir
	if err := writeSstpFiles(taskDir, t.nsName()); err != nil {
		return err
	}
	manifest, _ := json.Marshal(map[string]any{"slot": t.Slot, "hostname": t.Node.HostName, "server_ip": t.Node.IP, "port": endpoint.Port})
	if err := os.WriteFile(filepath.Join(taskDir, "persistent.json"), manifest, 0600); err != nil {
		return err
	}
	sstpc, _ := exec.LookPath("sstpc")
	command := []string{"netns", "exec", t.nsName(), "unshare", "--mount", "--propagation", "private", "--", "/bin/sh", filepath.Join(taskDir, t.nsName()+".launch"), taskDir, sstpc, endpoint.Host, t.nsName(), net.JoinHostPort(t.Node.IP, strconv.Itoa(endpoint.Port))}
	cmd := exec.CommandContext(t.workContext(), "ip", command...)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true, Pdeathsig: syscall.SIGKILL}
	logFile, err := os.OpenFile(filepath.Join(taskDir, "sstp.log"), os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	cmd.Stdout, cmd.Stderr = logFile, logFile
	if err := cmdStart(cmd); err != nil {
		logFile.Close()
		return fmt.Errorf("启动 SSTP 失败: %w", err)
	}
	t.ovpn = cmd // shared lifecycle holder for the Slot's tunnel process
	exited := make(chan struct{})
	go func() { _ = cmd.Wait(); _ = logFile.Close(); close(exited) }()
	deadline := time.Now().Add(45 * time.Second)
	for time.Now().Before(deadline) {
		ctx := t.workContext()
		if ctx.Err() != nil {
			return ctx.Err()
		}
		out, _ := cmdOutput(exec.CommandContext(ctx, "ip", "netns", "exec", t.nsName(), "ip", "-4", "-o", "addr", "show", "dev", "tun0"))
		if strings.Contains(string(out), "inet ") {
			_, peer := t.vethNames()
			if err := run("ip", "netns", "exec", t.nsName(), "ip", "route", "replace", t.Node.IP+"/32", "via", t.linkAddress(1), "dev", peer); err != nil {
				return err
			}
			return run("ip", "netns", "exec", t.nsName(), "ip", "route", "replace", "default", "dev", "tun0")
		}
		select {
		case <-exited:
			return fmt.Errorf("SSTP 提前退出，详见 %s", filepath.Join(taskDir, "sstp.log"))
		case <-time.After(250 * time.Millisecond):
		}
	}
	return fmt.Errorf("等待 SSTP PPP 接口就绪超时")
}
