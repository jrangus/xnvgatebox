package main

import (
	"context"
	"fmt"
	"net"
	"reflect"
	"strings"
	"time"
)

// opMu serializes a Slot's network operations. Cancellation gates new traffic
// immediately, while commands unwind before the next operation can touch netns.
func (t *Tunnel) workContext() context.Context {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.workCtx == nil {
		return context.Background()
	}
	return t.workCtx
}

func (t *Tunnel) resetWork() {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.workCtx, t.cancelWork = context.WithCancel(context.Background())
}

func (t *Tunnel) blockWork() {
	t.mu.Lock()
	if t.cancelWork != nil {
		t.cancelWork()
	}
	t.validating = false
	if t.Status != "stopped" {
		t.Status = "starting"
	}
	clients := make([]net.Conn, 0, len(t.clients))
	for c := range t.clients {
		clients = append(clients, c)
	}
	t.mu.Unlock()
	for _, c := range clients {
		_ = c.Close()
	}
}

func (t *Tunnel) blockForPolicy(reason string) {
	t.blockWork()
	t.mu.Lock()
	if t.Status != "stopped" {
		t.Status, t.Err = "blocked", reason
	}
	t.mu.Unlock()
}

func (m *Manager) claimNode(t *Tunnel, node Node, ctx context.Context) bool {
	for {
		m.mu.Lock()
		if m.tunnels[t.Slot] != t || ctx.Err() != nil {
			m.mu.Unlock()
			return false
		}
		lease := m.diagnostics[node.HostName]
		if lease == nil {
			for _, other := range m.diagnostics {
				if (node.IP != "" && other.ip == node.IP) || other.networkIndex == slotNetworkIndex(t.Slot) {
					lease = other
					break
				}
			}
		}
		if lease == nil {
			break // Keep the lock through the final claim below.
		}
		lease.cancel(errDiagnosticPreempted)
		m.mu.Unlock()
		select {
		case <-lease.done:
		case <-ctx.Done():
			return false
		}
	}
	defer m.mu.Unlock()
	if m.tunnels[t.Slot] != t || ctx.Err() != nil {
		return false
	}
	for _, other := range m.tunnels {
		if other == t {
			continue
		}
		other.mu.Lock()
		occupied := other.Status != "stopped" && other.Node.HostName == node.HostName
		other.mu.Unlock()
		if occupied {
			return false
		}
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.Status == "stopped" || ctx.Err() != nil {
		return false
	}
	t.Node, t.Status = node, "starting"
	return true
}

func (m *Manager) publishUp(t *Tunnel, ctx context.Context) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.tunnels[t.Slot] != t || ctx.Err() != nil {
		return false
	}
	t.mu.Lock()
	ip := t.ExitIP
	t.mu.Unlock()
	for _, other := range m.tunnels {
		if other == t {
			continue
		}
		other.mu.Lock()
		duplicate := other.Status == "up" && ip != "" && other.ExitIP == ip
		other.mu.Unlock()
		if duplicate {
			return false
		}
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if ctx.Err() != nil || t.workCtx != ctx || t.Status == "stopped" || t.egress == nil {
		return false
	}
	t.Status, t.Err = "up", ""
	return true
}

func waitForWork(ctx context.Context, d time.Duration) bool {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}

func (m *Manager) SetSlotPolicy(slot int, p SlotPolicy) error {
	normalized, err := normalizePolicy(p)
	if err != nil {
		return err
	}
	m.mu.RLock()
	t := m.tunnels[slot]
	m.mu.RUnlock()
	if t == nil {
		return fmt.Errorf("Slot 不存在")
	}
	if t.transport() == tunnelTransportSSTP {
		allowed := map[string]bool{}
		switch t.sourceCategory() {
		case exitSourceHome:
			allowed["strict_residential"], allowed["likely_residential"] = true, true
		case exitSourceNativeDC:
			allowed["datacenter"], allowed["business_isp"] = true, true
		}
		for _, kind := range normalized.AllowedIPTypes {
			if !allowed[kind] {
				return fmt.Errorf("持久 SSTP 策略不能跨越其出口来源分类")
			}
		}
		current := t.policySnapshot()
		if current.Country != "" && !strings.EqualFold(normalized.Country, current.Country) {
			return fmt.Errorf("持久 SSTP 出口国家由实际测量固定，不能改为其他国家")
		}
	}
	t.changeMu.Lock()
	defer t.changeMu.Unlock()
	return m.setSlotPolicyLocked(t, normalized)
}

func (m *Manager) setSlotPolicyLocked(t *Tunnel, normalized SlotPolicy) error {
	if !m.ownsTunnel(t) {
		return fmt.Errorf("Slot 已删除")
	}
	// Block before waiting on an in-flight handshake/query; cancellation kills
	// its child command and prevents it from publishing up under an old policy.
	t.mu.Lock()
	stopped := t.Status == "stopped"
	t.mu.Unlock()
	t.blockWork()
	t.opMu.Lock()
	old := t.policySnapshot()
	t.mu.Lock()
	oldPrevious := t.previousPolicy
	if !reflect.DeepEqual(old, normalized) {
		t.previousPolicy = &old
	}
	t.Policy = &normalized
	t.mu.Unlock()
	if err := m.saveState(); err != nil {
		t.mu.Lock()
		t.Policy = &old
		t.previousPolicy = oldPrevious
		if stopped {
			t.Status = "stopped"
		} else {
			t.Status = "blocked"
		}
		t.Err = "策略保存失败，Slot 保持阻断"
		t.mu.Unlock()
		t.opMu.Unlock()
		return err
	}
	if stopped {
		t.opMu.Unlock()
		return nil
	}
	oldHost := t.Node.HostName
	t.opMu.Unlock()
	m.reconnectTo(t, oldHost, nil)
	return nil
}

func (m *Manager) Resume(slot int) error {
	m.mu.RLock()
	t := m.tunnels[slot]
	m.mu.RUnlock()
	if t == nil {
		return fmt.Errorf("Slot 不存在")
	}
	t.changeMu.Lock()
	defer t.changeMu.Unlock()
	if !m.ownsTunnel(t) {
		return fmt.Errorf("Slot 已删除")
	}
	t.mu.Lock()
	stopped := t.Status == "stopped" || t.Status == "blocked" || t.Status == "waiting_for_nodes" || t.Status == "failed"
	t.mu.Unlock()
	if !stopped {
		return fmt.Errorf("Slot 已在运行或连接中")
	}
	t.mu.Lock()
	t.Status = "starting"
	t.mu.Unlock()
	m.reconnectTo(t, t.Node.HostName, nil)
	return nil
}

func (m *Manager) RollbackSlotPolicy(slot int) error {
	m.mu.RLock()
	t := m.tunnels[slot]
	m.mu.RUnlock()
	if t == nil {
		return fmt.Errorf("Slot 不存在")
	}
	t.changeMu.Lock()
	defer t.changeMu.Unlock()
	t.mu.Lock()
	before := t.previousPolicy
	t.mu.Unlock()
	if before == nil {
		return fmt.Errorf("没有上一次 Slot 策略")
	}
	normalized, err := normalizePolicy(*before)
	if err != nil {
		return err
	}
	return m.setSlotPolicyLocked(t, normalized)
}
