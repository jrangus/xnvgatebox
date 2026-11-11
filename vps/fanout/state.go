package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
)

// persistedTunnel 是隧道在磁盘上的形态。
// 只存重建所需的信息，运行态（netns、进程、监听）重启后重新建立。
type persistedTunnel struct {
	Slot           int            `json:"slot"`
	Port           int            `json:"port"`
	HostName       string         `json:"hostname"`
	CountryCode    string         `json:"country_code"`
	Country        string         `json:"country"`
	Config         string         `json:"config"`
	ServerIP       string         `json:"server_ip,omitempty"`
	SSTPCandidates []SstpEndpoint `json:"sstp_candidates,omitempty"`
	Transport      string         `json:"transport,omitempty"`
	SSTPPort       int            `json:"sstp_port,omitempty"`
	SourceCategory string         `json:"source_category,omitempty"`
	SourceName     string         `json:"source_name,omitempty"`
	Native         bool           `json:"native,omitempty"`
	// SOCKS5 凭据要存盘：用户已经把它分发给客户端了，重启后变掉等于全断
	SocksUser string `json:"socks_user,omitempty"`
	SocksPass string `json:"socks_pass,omitempty"`
	// PrevHost 非空表示上次换节点只做了一半：隧道已经指向新节点，
	// 但入站还绑在这个旧节点上。恢复时照着它把入站接回来。
	PrevHost       string      `json:"prev_host,omitempty"`
	Policy         *SlotPolicy `json:"policy,omitempty"`
	Stopped        bool        `json:"stopped,omitempty"`
	PreviousPolicy *SlotPolicy `json:"previous_policy,omitempty"`
}

type persistedState struct {
	Tunnels      []persistedTunnel `json:"tunnels"`
	DeletedSlots []int             `json:"deleted_slots,omitempty"`
}

func statePath(dir string) string { return filepath.Join(dir, "state.json") }

const stateJournal = ".state-transaction.json"

// saveState 把当前隧道写入磁盘，供重启后恢复。
func (m *Manager) saveState() error {
	m.saveMu.Lock()
	defer m.saveMu.Unlock()
	if m.shuttingDown {
		return fmt.Errorf("服务正在停止，保留最后提交的运行意图")
	}
	var st persistedState
	m.mu.RLock()
	for slot := range m.deletedSlots {
		st.DeletedSlots = append(st.DeletedSlots, slot)
	}
	m.mu.RUnlock()
	for _, t := range m.Tunnels() {
		// Preserve stopped intent too; starting/failed Slots must not disappear
		// merely because they were waiting for a candidate at shutdown.
		t.mu.Lock()
		st.Tunnels = append(st.Tunnels, persistedTunnel{
			Slot:           t.Slot,
			Port:           t.Port,
			HostName:       t.Node.HostName,
			CountryCode:    t.Node.CountryCode,
			Country:        t.Node.Country,
			Config:         t.Node.Config,
			ServerIP:       t.Node.IP,
			SSTPCandidates: append([]SstpEndpoint(nil), t.Node.SSTPCandidates...),
			Transport:      t.transport(),
			SSTPPort:       t.SSTPPort,
			SourceCategory: t.sourceCategory(),
			SourceName:     t.SourceName,
			Native:         t.Native,
			SocksUser:      t.Cred.User,
			SocksPass:      t.Cred.Pass,
			PrevHost:       t.prevHost,
			Policy:         t.Policy,
			Stopped:        t.Status == "stopped",
			PreviousPolicy: t.previousPolicy,
		})
		t.mu.Unlock()
	}

	blob, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	tx, err := beginConfigTransaction(m.workDir, stateJournal, []string{"state.json"})
	if err != nil {
		return err
	}
	fail := func(cause error) error {
		if rollbackErr := tx.rollback(); rollbackErr != nil {
			return fmt.Errorf("状态提交失败且回滚未完成，保留恢复记录: %w", rollbackErr)
		}
		return cause
	}
	if err := atomicConfigWrite(statePath(m.workDir), blob); err != nil {
		return fail(err)
	}
	if m.stateWriteHook != nil {
		if err := m.stateWriteHook("before_commit"); err != nil {
			return fail(err)
		}
	}
	if err := tx.commit(); err != nil {
		return fail(err)
	}
	if err := m.saveSlotHealth(); err != nil {
		log.Printf("保存出口观察快照失败: %v", err)
	}
	return nil
}

// restoreState 读回上次的隧道并逐条拉起。
// 节点配置一并存了盘，所以即使 VPN Gate 列表里该节点已消失也能重建。
func (m *Manager) restoreState() (int, error) {
	if err := recoverConfigTransaction(m.workDir, stateJournal, []string{"state.json"}); err != nil {
		return 0, err
	}
	blob, err := os.ReadFile(statePath(m.workDir))
	if os.IsNotExist(err) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}

	st, err := decodePersistedState(blob, m.maxSlots, residentialOnly())
	if err != nil {
		return 0, err
	}
	tunnels, err := prepareRestoredTunnels(st, m.nodes)
	if err != nil {
		return 0, err
	}
	// Publish the entire validated batch before starting any worker. A malformed
	// later Slot or tombstone must not leave a partially restored manager.
	m.mu.Lock()
	for _, slot := range st.DeletedSlots {
		m.deletedSlots[slot] = true
	}
	for _, t := range tunnels {
		m.tunnels[t.Slot] = t
	}
	m.mu.Unlock()
	for _, t := range tunnels {
		if t.Status != "stopped" {
			t.resetWork()
			go m.restoreTunnel(t, t.workContext())
		}
	}
	return len(tunnels), nil
}

// Shared by real startup and the offline checker. No file writes, workers,
// random credentials or global settings changes occur during validation.
func decodePersistedState(blob []byte, maxSlots int, residential bool) (*persistedState, error) {
	var st *persistedState
	if err := json.Unmarshal(blob, &st); err != nil || st == nil {
		return nil, fmt.Errorf("解析状态文件失败")
	}
	if maxSlots < 1 {
		return nil, fmt.Errorf("Slot 上限无效")
	}
	seen := map[int]bool{}
	ports := map[int]bool{}
	for i := range st.Tunnels {
		p := &st.Tunnels[i]
		if p.Slot < 1 || p.Slot > maxSlots || seen[p.Slot] || ports[p.Port] || p.Port < 1 || p.Port > 65535 {
			return nil, fmt.Errorf("持久化 Slot 身份或端口无效")
		}
		seen[p.Slot] = true
		ports[p.Port] = true
		policy := defaultSlotPolicyForMode(p.CountryCode, residential)
		if p.Policy != nil {
			policy = *p.Policy
		}
		normalized, err := normalizePolicy(policy)
		if err != nil {
			return nil, fmt.Errorf("Slot %d 策略无效", p.Slot)
		}
		p.Policy = &normalized
		if p.Transport == "" {
			p.Transport = tunnelTransportOpenVPN
		}
		if p.Transport != tunnelTransportOpenVPN && p.Transport != tunnelTransportSSTP {
			return nil, fmt.Errorf("Slot %d 持久化出口协议无效", p.Slot)
		}
		if p.SourceCategory == "" {
			p.SourceCategory = exitSourceStable
		}
		if p.Transport == tunnelTransportOpenVPN {
			if p.SourceCategory != exitSourceStable || p.SSTPPort != 0 {
				return nil, fmt.Errorf("Slot %d 稳定出口来源无效", p.Slot)
			}
		} else {
			if (p.SourceCategory != exitSourceHome && p.SourceCategory != exitSourceNativeDC) || p.SSTPPort < 1 || p.SSTPPort > 65535 || !sstpPublicIPv4(p.ServerIP) {
				return nil, fmt.Errorf("Slot %d 持久 SSTP 来源无效", p.Slot)
			}
			candidateNode := Node{HostName: p.HostName, IP: p.ServerIP, SSTPCandidates: p.SSTPCandidates}
			matched := false
			for _, endpoint := range p.SSTPCandidates {
				matched = matched || (endpoint.Port == p.SSTPPort && officialSstpEndpoint(candidateNode, endpoint))
			}
			if !matched {
				return nil, fmt.Errorf("Slot %d 持久 SSTP 端点无效", p.Slot)
			}
		}
		if p.PreviousPolicy != nil {
			before, err := normalizePolicy(*p.PreviousPolicy)
			if err != nil {
				return nil, fmt.Errorf("上一次 Slot 策略无效")
			}
			p.PreviousPolicy = &before
		}
		// Only a completely absent legacy pair may be generated. Rotating an
		// existing half-pair silently would invalidate deployed clients.
		if p.SocksUser != "" || p.SocksPass != "" {
			if err := validateCred(SocksCred{User: p.SocksUser, Pass: p.SocksPass}); err != nil {
				return nil, fmt.Errorf("Slot %d 持久化 SOCKS 凭据无效", p.Slot)
			}
		}
	}
	for _, slot := range st.DeletedSlots {
		if slot < 1 || slot > maxSlots || seen[slot] {
			return nil, fmt.Errorf("删除记录无效")
		}
		seen[slot] = true
	}
	return st, nil
}

func prepareRestoredTunnels(st *persistedState, nodes []Node) ([]*Tunnel, error) {
	// 从当前节点列表补回地区、延迟等元数据；节点已下线时退回存盘的最小信息
	known := map[string]Node{}
	for _, n := range nodes {
		known[n.HostName] = n
	}

	tunnels := make([]*Tunnel, 0, len(st.Tunnels))
	for _, p := range st.Tunnels {
		node, ok := known[p.HostName]
		if !ok || p.Transport == tunnelTransportSSTP {
			// 节点已从 VPN Gate 列表消失，用存盘的信息重建
			// SSTP 则无论当前清单是否还有同名节点，都必须继续使用当时
			// 实测并持久化的 IP、证书主机名和端口；同名记录的新地址必须
			// 重新检测，不能在重启恢复时悄悄替换安全边界。
			node = Node{
				HostName:       p.HostName,
				CountryCode:    p.CountryCode,
				Country:        p.Country,
				IP:             p.ServerIP,
				SSTPCandidates: append([]SstpEndpoint(nil), p.SSTPCandidates...),
			}
		}
		if p.Transport == tunnelTransportSSTP {
			node.Config = fmt.Sprintf("proto tcp\nremote %s %d\n", node.IP, p.SSTPPort)
		} else if node.Config == "" {
			node.Config = p.Config
		}
		// 从旧版本升上来的状态文件没有凭据字段，补一套新的
		cred := SocksCred{User: p.SocksUser, Pass: p.SocksPass}
		if cred.User == "" && cred.Pass == "" {
			gen, err := newSocksCred()
			if err != nil {
				return nil, fmt.Errorf("生成 SOCKS5 凭据失败: %w", err)
			}
			cred = gen
		}
		t := &Tunnel{
			Slot:           p.Slot,
			Port:           p.Port,
			Node:           node,
			Status:         "starting",
			Cred:           cred,
			Policy:         p.Policy,
			previousPolicy: p.PreviousPolicy,
			Transport:      p.Transport,
			SSTPPort:       p.SSTPPort,
			SourceCategory: p.SourceCategory,
			SourceName:     p.SourceName,
			Native:         p.Native,
		}
		bindingHost := p.PrevHost
		if bindingHost == "" {
			// Recovery may choose another candidate even when shutdown was
			// clean. Remember the original binding so it follows this Slot.
			bindingHost = p.HostName
		}
		t.setPrevHost(bindingHost)
		if p.Stopped {
			t.Status = "stopped"
		}
		tunnels = append(tunnels, t)
	}
	return tunnels, nil
}

// restoreTunnel 拉起一条恢复出来的隧道，顺手把上次没做完的换节点收尾。
func (m *Manager) restoreTunnel(t *Tunnel, ctx context.Context) {
	prev := t.prevHostOf()
	m.bringUpPersistContext(t, true, true, ctx)
	if ctx.Err() != nil || prev == "" || t.Status != "up" {
		return
	}
	t.opMu.Lock()
	defer t.opMu.Unlock()
	if ctx.Err() != nil || !m.tunnelActive(t) {
		return
	}
	// 上次换节点改完隧道就中断了，入站还指着旧节点。不接回来的话它会一直
	// 显示成"未绑定出口"，流量悄悄走直连——用户看不出哪里不对。
	if err := m.rebind(prev, t); err != nil {
		t.blockForPolicy("恢复绑定配置失败，Slot 保持阻断")
		_ = m.saveState()
		log.Printf("恢复时把入站接回出口 %d 失败: %v", t.Slot, err)
		return
	}
	log.Printf("出口 %d 上次换节点没收尾，已把原来绑着 %s 的入站接到 %s",
		t.Slot, prev, t.Node.HostName)
	t.setPrevHost("")
	if err := m.saveState(); err != nil {
		log.Printf("保存状态失败: %v", err)
	}
}
