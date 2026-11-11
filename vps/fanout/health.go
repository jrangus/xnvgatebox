package main

import (
	"log"
	"time"
)

const (
	healthInterval = 10 * time.Second
	healthFailures = 2 // 连续失败几次才判定掉线，避免网络抖动误杀
	healthTimeout  = 6 * time.Second
)

// WatchHealth 周期检查每条隧道是否还能出网，掉线的自动换节点重连。
// VPN Gate 是志愿者节点，运行中掉线很常见。
func (m *Manager) WatchHealth() {
	fails := map[int]int{}

	for range time.Tick(healthInterval) {
		for _, t := range m.Tunnels() {
			t.mu.Lock()
			status := t.Status
			t.mu.Unlock()
			if status != "up" {
				continue
			}
			if t.snapshot().Status == "blocked" {
				t.blockForPolicy("画像证据已过期或不满足当前策略")
				m.reconnect(t, t.snapshot().Node.HostName)
				continue
			}
			if m.tunnelHealthy(t) {
				fails[t.Slot] = 0
				continue
			}
			t.mu.Lock()
			blocked := t.Status == "blocked"
			t.mu.Unlock()
			if blocked {
				fails[t.Slot] = 0
				m.reconnect(t, t.Node.HostName)
				continue
			}

			fails[t.Slot]++
			if fails[t.Slot] < healthFailures {
				log.Printf("隧道 %d (%s) 探测失败 %d 次", t.Slot, t.Node.HostName, fails[t.Slot])
				continue
			}

			log.Printf("隧道 %d (%s) 已掉线，正在换节点重连", t.Slot, t.Node.HostName)
			fails[t.Slot] = 0
			m.reconnect(t, t.Node.HostName)
		}
	}
}

// tunnelHealthy 判断隧道是否还真的走在 VPN 上。
//
// 只看"能不能出网"是不够的：netns 通过 veth 走母机 NAT，
// openvpn 死掉后照样能出网，只是出口变回了母机 IP。
// 所以要比对出口 IP 是否仍是建立隧道时拿到的那个。
func (m *Manager) tunnelHealthy(t *Tunnel) bool {
	t.opMu.Lock()
	defer t.opMu.Unlock()
	ctx := t.workContext()
	got, latency, err := t.probeSocksExitIPWithLatency()
	if err != nil {
		return false
	}
	if ctx.Err() != nil {
		return false
	}
	// 出口 IP 变了说明 VPN 已经断开，流量退回了母机
	if got != t.ExitIP {
		t.blockForPolicy("实际出口 IP 已变化，必须重新建立基线")
		return false
	}
	if t.Policy != nil {
		image := t.egressSnapshot(false)
		if image == nil || t.policySnapshot().checkImageForProtocol(*image, t.transport()) != nil || t.policySnapshot().checkLatency(latency) != nil {
			t.blockForPolicy("当前画像或本机 SOCKS 延迟不满足 Slot 策略")
			return false
		}
	}
	t.mu.Lock()
	t.LatencyMS = latency
	t.mu.Unlock()
	return true
}

// reconnect 就地把一条隧道换到别的节点上，保持槽位与端口不变，
// 这样已经分发出去的客户端配置仍然可用。
//
// oldHost 必须是本次重连前那条隧道真正绑着的节点名。调用方若已经
// 改过 t.Node（比如手动换节点），就要把改之前的名字传进来，
// 否则 rebind 找不到旧绑定，入站会掉成孤儿。
func (m *Manager) reconnect(t *Tunnel, oldHost string) {
	t.changeMu.Lock()
	defer t.changeMu.Unlock()
	t.mu.Lock()
	up := t.Status == "up" || t.Status == "blocked"
	t.mu.Unlock()
	if !up {
		return
	}
	m.reconnectTo(t, oldHost, nil)
}

func (m *Manager) reconnectTo(t *Tunnel, oldHost string, node *Node) {
	t.blockWork()
	t.opMu.Lock()
	if !m.tunnelActive(t) {
		t.opMu.Unlock()
		return
	}
	t.mu.Lock()
	t.Status, t.Err, t.ExitIP = "starting", "正在按 Slot 策略重新验活", ""
	if node != nil {
		t.Node = *node
	}
	if t.prevHost == "" {
		t.prevHost = oldHost
	}
	t.mu.Unlock()
	if err := m.saveState(); err != nil {
		log.Printf("保存状态失败: %v", err)
	}
	t.teardownNetns()
	t.resetWork()
	ctx := t.workContext()
	t.opMu.Unlock()
	go func() {
		m.bringUpPersistContext(t, false, true, ctx)
		if ctx.Err() != nil || t.Status != "up" || !m.tunnelActive(t) {
			return
		}
		t.opMu.Lock()
		defer t.opMu.Unlock()
		if ctx.Err() != nil || !m.tunnelActive(t) {
			return
		}
		bindingHost := t.prevHostOf()
		if t.Node.HostName != bindingHost {
			if err := m.rebind(bindingHost, t); err != nil {
				t.blockForPolicy("绑定配置应用失败，已阻断，请修复配置后重新启动 Slot")
				_ = m.saveState()
				log.Printf("重连后同步绑定失败: %v", err)
				return
			}
		} else if err := m.resync(t); err != nil {
			t.blockForPolicy("出站配置应用失败，已阻断，请修复配置后重新启动 Slot")
			_ = m.saveState()
			log.Printf("重连后重写出站失败: %v", err)
			return
		}
		t.setPrevHost("")
		if err := m.saveState(); err != nil {
			log.Printf("保存状态失败: %v", err)
		}
	}()
}
