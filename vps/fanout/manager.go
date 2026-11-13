package main

import (
	"context"
	"fmt"
	"log"
	"os/exec"
	"sort"
	"strings"
	"sync"
	"time"
)

// Manager 维护所有隧道，负责分配槽位与端口。
type Manager struct {
	mu              sync.RWMutex
	tunnels         map[int]*Tunnel
	nodes           []Node
	fetched         time.Time
	workDir         string
	evidenceDir     string
	maxSlots        int
	jobs            JobStore
	saveMu          sync.Mutex
	shuttingDown    bool // protected by saveMu; transient teardown is not user intent
	deletedSlots    map[int]bool
	localEvidence   map[string]Node
	stateWriteHook  func(string) error
	credentialApply func(*Tunnel) error
	connectBudget   *connectBudget
	observations    map[string]CheckResult
	diagnostics     map[string]*diagnosticLease
	console         *Console
}

func NewManager(maxSlots int, workDir string) *Manager {
	return &Manager{
		tunnels:       map[int]*Tunnel{},
		workDir:       workDir,
		evidenceDir:   workDir,
		maxSlots:      maxSlots,
		deletedSlots:  map[int]bool{},
		localEvidence: map[string]Node{},
		connectBudget: newConnectBudget(defaultCheckParallelism),
		observations:  map[string]CheckResult{},
		diagnostics:   map[string]*diagnosticLease{},
	}
}

// RefreshNodes 重新拉取节点列表。
func (m *Manager) RefreshNodes() (int, error) {
	nodes, err := fetchNodes(60 * time.Second)
	if err != nil {
		return 0, err
	}
	m.mu.Lock()
	m.nodes = nodes
	m.fetched = time.Now()
	m.mu.Unlock()
	// Never wait for plan changes from a reconnect worker: deleting a Slot may
	// be waiting for that worker to finish. A buffered wake coalesces refreshes.
	if m.console != nil {
		select {
		case m.console.poolChanged <- struct{}{}:
		default:
		}
	}
	return len(nodes), nil
}

func (m *Manager) Nodes() ([]Node, time.Time) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]Node, len(m.nodes))
	copy(out, m.nodes)
	for i, n := range out {
		if local, ok := m.localEvidence[n.HostName]; ok && local.Config == n.Config && freshCandidateImage(local) != nil {
			out[i] = local
		}
		if out[i].OpenVPNEgress != nil && freshCandidateImage(out[i]) == nil {
			out[i].IPType, out[i].ISP, out[i].ASN, out[i].ExpectedExitIP = "unknown", "", "", ""
			out[i].Residential = false
			out[i].OpenVPNStatus = "stale"
		}
	}
	return out, m.fetched
}

func (m *Manager) Tunnels() []*Tunnel {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]*Tunnel, 0, len(m.tunnels))
	for _, t := range m.tunnels {
		out = append(out, t)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Slot < out[j].Slot })
	return out
}

// freeSlot 找一个未占用的槽位。槽位同时决定端口与网段。
func (m *Manager) freeSlot() (int, error) {
	for i := 1; i <= m.maxSlots; i++ {
		if _, used := m.tunnels[i]; !used {
			return i, nil
		}
	}
	return 0, fmt.Errorf("槽位已满（上限 %d）", m.maxSlots)
}

// Start 为指定节点开一条隧道，返回分配到的本地端口。
func (m *Manager) Start(node Node) (*Tunnel, error) {
	return m.StartWithPolicy(node, defaultSlotPolicy(node.CountryCode))
}

func (m *Manager) StartWithPolicy(node Node, policy SlotPolicy) (*Tunnel, error) {
	policy, err := normalizePolicy(policy)
	if err != nil {
		return nil, err
	}
	m.mu.Lock()
	for _, other := range m.tunnels {
		other.mu.Lock()
		occupied := node.HostName != "" && other.Status != "stopped" && other.Node.HostName == node.HostName
		other.mu.Unlock()
		if occupied {
			m.mu.Unlock()
			return nil, fmt.Errorf("节点已被其他 Slot 占用")
		}
	}
	slot, err := m.freeSlot()
	if err != nil {
		m.mu.Unlock()
		return nil, err
	}
	// 端口随机取，避免固定规律撞上机器上的其他服务
	taken := map[int]bool{}
	for _, other := range m.tunnels {
		taken[other.Port] = true
	}
	port, fixed, err := fixedSlotPort(slot)
	if err != nil {
		m.mu.Unlock()
		return nil, err
	}
	if fixed {
		if taken[port] || !portAvailable(port) {
			m.mu.Unlock()
			return nil, fmt.Errorf("槽位 %d 的固定端口 %d 已被占用", slot, port)
		}
	} else {
		port, err = freeRandomPort(taken)
		if err != nil {
			m.mu.Unlock()
			return nil, err
		}
	}
	cred, err := newSocksCred()
	if err != nil {
		m.mu.Unlock()
		return nil, err
	}
	t := &Tunnel{
		Slot:           slot,
		Port:           port,
		Node:           node,
		Status:         "starting",
		Since:          time.Now(),
		Cred:           cred,
		Policy:         &policy,
		Transport:      tunnelTransportOpenVPN,
		SourceCategory: exitSourceStable,
		SourceName:     "VPN Gate · xnvgatebox stable",
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

// bringUp 把一条隧道拉起来。
//
// notify 决定成功后是否立刻重建后端配置。换节点重连时要传 false：
// 那条路径随后会调 rebind/resync 把入站改绑到新节点，在那之前重建配置
// 会因为入站还指着旧节点名而把路由规则丢掉。
func (m *Manager) bringUp(t *Tunnel, notify bool) {
	m.bringUpPersist(t, notify, false)
}

// 自动重连的退避区间：一轮候选全挂后等一会儿再刷新节点列表重来，
// 别把死节点列表打爆，也别让恢复拖太久。
const (
	reconnectBackoffMin = 5 * time.Second
	reconnectBackoffMax = 60 * time.Second
)

// bringUpPersist 把一条隧道拉起来。
//
// persist=false：走一轮候选，全失败保留 waiting_for_nodes，不放宽策略。
// persist=true（自动重连 / 重启恢复）：一轮全失败不放弃，退避后刷新节点列表再来一轮，
// 一直循环到连上或这条隧道被用户停掉。VPN Gate 死节点多，"当前都不可用"往往只是
// 这一批候选恰好都挂了，过一会儿就有新节点，不该让出口永久躺死。
func (m *Manager) bringUpPersist(t *Tunnel, notify bool, persist bool) {
	m.bringUpPersistContext(t, notify, persist, t.workContext())
}

func (m *Manager) bringUpPersistContext(t *Tunnel, notify, persist bool, ctx context.Context) {
	backoff := reconnectBackoffMin
	for {
		if ctx.Err() != nil || !m.tunnelActive(t) {
			return
		}
		if m.tryCandidatesContext(t, notify, ctx) {
			return
		}
		if ctx.Err() != nil {
			return
		}
		// 隧道已被用户停掉或从管理器移除，别再重试
		if !persist || !m.tunnelActive(t) {
			if persist {
				return
			}
			t.mu.Lock()
			t.Status = "waiting_for_nodes"
			t.mu.Unlock()
			if serr := m.saveState(); serr != nil {
				log.Printf("保存状态失败: %v", serr)
			}
			return
		}

		t.mu.Lock()
		t.Status = "waiting_for_nodes"
		t.Err = fmt.Sprintf("暂无符合策略的节点，%.0f 秒后重试", backoff.Seconds())
		t.mu.Unlock()
		if err := m.saveState(); err != nil {
			log.Printf("保存等待状态失败: %v", err)
		}
		log.Printf("隧道 %d 一轮候选均失败，%.0f 秒后刷新节点重试", t.Slot, backoff.Seconds())
		if !waitForWork(ctx, backoff) {
			return
		}
		if !m.tunnelActive(t) {
			return
		}
		if _, err := m.RefreshNodes(); err != nil {
			log.Printf("重试前刷新节点列表失败: %v", err)
		}
		if backoff < reconnectBackoffMax {
			backoff *= 2
			if backoff > reconnectBackoffMax {
				backoff = reconnectBackoffMax
			}
		}
	}
}

// tryCandidates 走一轮候选节点，成功返回 true。失败不改 Status（留给调用方决定）。
func (m *Manager) tryCandidates(t *Tunnel, notify bool) bool {
	return m.tryCandidatesContext(t, notify, t.workContext())
}

func (m *Manager) tryCandidatesContext(t *Tunnel, notify bool, ctx context.Context) bool {
	t.opMu.Lock()
	defer t.opMu.Unlock()
	if ctx.Err() != nil {
		return false
	}
	// VPN Gate 是志愿者节点，列表里有相当比例已下线或满员（AUTH_FAILED），
	// 连不上就顺着候选列表换下一个，不必让用户手动试。
	candidates := m.candidatesFor(t)
	for i, node := range candidates {
		if ctx.Err() != nil || !m.tunnelActive(t) {
			return false
		}
		// 其他隧道可能在重试期间占用了这个节点，跳过以免多个端口撞同一出口 IP
		// The previous candidate's kill-switch rules are keyed by its remote
		// endpoint. Tear them down before replacing t.Node, otherwise a stale
		// allow rule can block the next candidate or leave an old endpoint open.
		if i > 0 {
			t.teardownNetns()
		}
		if !m.claimNode(t, node, ctx) {
			continue
		}
		if i > 0 {
			t.mu.Lock()
			t.Err = fmt.Sprintf("已换到第 %d 个候选节点", i+1)
			t.mu.Unlock()
		}

		err := m.tryNode(t)
		if err == nil && m.publishUp(t, ctx) {
			if serr := m.saveState(); serr != nil {
				log.Printf("保存状态失败: %v", serr)
			}
			if notify {
				m.notifyPanel()
			}
			return true
		}
		if err == nil {
			err = fmt.Errorf("Slot 操作已取消或出口与另一 Slot 重复")
		}
		log.Printf("隧道 %d 候选 %s 失败: %v", t.Slot, node.HostName, err)
		t.teardownNetns()
		if ctx.Err() != nil {
			return false
		}
		t.mu.Lock()
		if t.cooldown == nil {
			t.cooldown = map[string]time.Time{}
		}
		t.cooldown[node.HostName] = time.Now().Add(30 * time.Second)
		t.Err = firstLine(fmt.Sprint(err))
		t.mu.Unlock()
	}
	log.Printf("隧道 %d 本轮没有符合策略的候选", t.Slot)
	return false
}

// tunnelActive 判断这条隧道是否还归管理器所有且未被用户停掉。
// 用指针比对：Stop 会从 map 里删除并把 Status 置 stopped，
// 重连循环据此退出，避免对着一条已经不存在的隧道空转。
func (m *Manager) tunnelActive(t *Tunnel) bool {
	t.mu.Lock()
	stopped := t.Status == "stopped"
	t.mu.Unlock()
	if stopped {
		return false
	}
	m.mu.RLock()
	cur, ok := m.tunnels[t.Slot]
	m.mu.RUnlock()
	return ok && cur == t
}

// tryNode 尝试用当前节点把隧道拉起来。
func (m *Manager) tryNode(t *Tunnel) error {
	t.probePhase("waiting_capacity")
	release, err := m.connectBudget.acquire(t.workContext(), t.Slot > 0)
	if err != nil {
		return err
	}
	defer release()

	t.clearEgress()
	t.probePhase("setup")
	if err := t.setupNetns(); err != nil {
		return err
	}
	t.probePhase("connecting")
	if t.transport() == tunnelTransportSSTP {
		if err := t.startSSTP(m.workDir); err != nil {
			return err
		}
	} else if err := t.startOpenVPN(m.workDir); err != nil {
		return err
	}
	if t.listener == nil {
		if err := t.serve(); err != nil {
			return err
		}
	}
	t.probePhase("baseline")
	ip, err := t.probeExitIP()
	if err != nil {
		return err
	}
	if host := hostPublicIP(); host != "" && ip == host {
		return fmt.Errorf("%s 未提供独立出口，namespace 回落到母机公网 IP %s", strings.ToUpper(t.transport()), host)
	}
	t.mu.Lock()
	t.ExitIP = ip
	t.mu.Unlock()
	t.probePhase("profile")
	var image EgressProfile
	if t.transport() == tunnelTransportSSTP {
		image = EgressProfile{IP: ip, Protocol: tunnelTransportSSTP, IPType: "unknown", Reason: "sstp_pool_unclassified", Confidence: "unknown", IntelligenceStatus: "not_configured"}
	} else {
		image = lookupOpenVPNEgressContext(t.workContext(), m.evidenceDir, ip)
	}
	if !m.tunnelActive(t) {
		return fmt.Errorf("画像查询期间 Slot 已停止")
	}
	policy := t.policySnapshot()
	if err := policy.checkImageForProtocol(image, t.transport()); err != nil {
		return err
	}
	t.setValidating(true)
	t.probePhase("verify_exit")
	actual, latency, err := t.probeSocksExitIPWithLatency()
	t.setValidating(false)
	if err != nil {
		return fmt.Errorf("固定 SOCKS5 出口验活失败: %w", err)
	}
	if actual != ip {
		return fmt.Errorf("expected_exit_ip 与 actual_exit_ip 不一致: %s / %s", ip, actual)
	}
	if err := policy.checkLatency(latency); err != nil {
		return err
	}
	if !m.tunnelActive(t) || t.workContext().Err() != nil {
		return fmt.Errorf("Slot 操作已取消")
	}
	t.mu.Lock()
	t.LatencyMS = latency
	t.mu.Unlock()
	if err := t.acceptExitEvidence(ip, actual, image); err != nil {
		return err
	}
	if t.transport() == tunnelTransportOpenVPN {
		public := image
		public.Raw = nil
		t.mu.Lock()
		t.Node.OpenVPNEgress = &public
		t.Node.ExpectedExitIP, t.Node.OpenVPNStatus, t.Node.IPType = ip, "passed", image.IPType
		t.Node.ISP, t.Node.ASN = stringValue(image.ISP), stringValue(image.ASN)
		t.Node.Residential = image.IPType == "strict_residential" || image.IPType == "likely_residential"
		observed := t.Node
		t.mu.Unlock()
		m.mu.Lock()
		m.localEvidence[observed.HostName] = observed
		m.mu.Unlock()
	}
	return nil
}

// candidatesFor 以这条隧道当前的节点打头，后面跟上同地区的其他节点作为备选。
//
// 打头的一定是 t.Node：自动重连的目标是把这条出口恢复原样，先试原节点。
// 备选会避开用户手动换掉过的节点——那些是他明确不想要的 IP，
// 让重连悄悄换回去等于撤销了他的操作。
func (m *Manager) candidatesFor(t *Tunnel) []Node {
	policy := t.policySnapshot()
	t.mu.Lock()
	first := t.Node
	t.mu.Unlock()
	if t.transport() == tunnelTransportSSTP {
		if first.HostName == "" || m.nodeInUse(first.HostName, t.Slot) {
			return nil
		}
		return []Node{first}
	}
	avoid := t.swapAvoid()
	out := []Node{}
	eligible := func(n Node) bool {
		t.mu.Lock()
		until := t.cooldown[n.HostName]
		t.mu.Unlock()
		if time.Now().Before(until) {
			return false
		}
		image := freshCandidateImage(n)
		if image != nil {
			return policy.checkImage(*image) == nil
		}
		return policy.Country == "" || n.CountryCode == "" || strings.EqualFold(policy.Country, n.CountryCode)
	}
	if first.HostName != "" && !m.nodeInUse(first.HostName, t.Slot) && eligible(first) {
		out = append(out, first)
	}
	candidates := m.policyCandidates(policy, avoid, t.Slot)
	t.mu.Lock()
	failedUntil := make(map[string]time.Time, len(t.cooldown))
	for host, until := range t.cooldown {
		failedUntil[host] = until
	}
	t.mu.Unlock()
	// A round can outlast the cooldown. Keep untried candidates ahead of
	// expired failures so the six-probe budget cannot starve the rest of the
	// pool by retrying the same highest-ranked failures every round.
	sort.SliceStable(candidates, func(i, j int) bool {
		return failedUntil[candidates[i].HostName].Before(failedUntil[candidates[j].HostName])
	})
	for _, n := range candidates {
		if len(out) >= 6 {
			break
		}
		if n.HostName != first.HostName && eligible(n) {
			out = append(out, n)
		}
	}
	return out
}

// Stop 停掉运行态，保留 Slot 身份、端口和策略。
func (m *Manager) Stop(slot int) error {
	invalidateInbounds()
	m.mu.Lock()
	t, ok := m.tunnels[slot]

	m.mu.Unlock()
	if !ok {
		return fmt.Errorf("槽位 %d 没有运行中的隧道", slot)
	}
	t.changeMu.Lock()
	defer t.changeMu.Unlock()
	t.stop()
	if err := m.saveState(); err != nil {
		log.Printf("保存状态失败: %v", err)
		m.notifyPanel()
		return err
	}
	m.notifyPanel()
	return nil
}

// Delete is explicit: stopping reserves the Slot; deletion frees its identity.
// Export retains a block tombstone until that Slot is deliberately recreated.
func (m *Manager) Delete(slot int) error {
	if m.console != nil {
		return m.console.deleteSlot(slot)
	}
	return m.deleteSlot(slot)
}

func (m *Manager) deleteSlot(slot int) error {
	m.mu.RLock()
	t := m.tunnels[slot]
	m.mu.RUnlock()
	if t == nil {
		return fmt.Errorf("Slot 不存在")
	}
	t.changeMu.Lock()
	defer t.changeMu.Unlock()
	t.stop()
	m.mu.Lock()
	delete(m.tunnels, slot)
	m.deletedSlots[slot] = true
	m.mu.Unlock()
	if err := m.saveState(); err != nil {
		return err
	}
	m.notifyPanel()
	return nil
}

func (m *Manager) exportTunnels() []*Tunnel {
	out := m.Tunnels()
	m.mu.RLock()
	defer m.mu.RUnlock()
	for slot := range m.deletedSlots {
		out = append(out, &Tunnel{Slot: slot, Status: "stopped"})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Slot < out[j].Slot })
	return out
}

// Swap 把一条隧道换到同地区的另一个节点上，端口与已分发的客户端配置保持不变。
//
// 与健康检查的自动重连不同：那边优先重连原节点（目标是恢复），
// 这里用户是嫌当前出口 IP 不好用，必须真的换一个。
//
// 换过的节点会记进历史一并避开。只排除"当前这个"是不够的：
// A 换成 B 之后 A 就空出来了，而候选是按速度排的，A 往往又排在最前面，
// 于是再点一次就换回了 A。历史让每次点击都真的换一个没用过的。
func (m *Manager) Swap(slot int) error {
	m.mu.RLock()
	t, ok := m.tunnels[slot]
	m.mu.RUnlock()
	if !ok {
		return fmt.Errorf("槽位 %d 没有运行中的隧道", slot)
	}
	if t.transport() == tunnelTransportSSTP {
		return fmt.Errorf("持久 SSTP 出口不能切换为 OpenVPN 节点")
	}
	t.changeMu.Lock()
	defer t.changeMu.Unlock()
	if t.Status == "stopped" {
		return fmt.Errorf("Slot 已停止，请先启动")
	}
	if t.Status == "starting" {
		return fmt.Errorf("这个出口正在连接中，稍等一下")
	}

	node, err := m.pickSwapTarget(t)
	if err != nil {
		return err
	}
	oldHost := t.Node.HostName
	m.reconnectTo(t, oldHost, &node)
	return nil
}

// SwapTo replaces a running Slot with a user-selected node from the shared
// validated pool.  The country is kept stable so a manual choice cannot
// silently violate the Slot's current policy.
func (m *Manager) SwapTo(slot int, host string) error {
	m.mu.RLock()
	t, ok := m.tunnels[slot]
	var node Node
	for _, candidate := range m.nodes {
		if candidate.HostName == host {
			node = candidate
			break
		}
	}
	m.mu.RUnlock()
	if !ok {
		return fmt.Errorf("槽位 %d 没有运行中的隧道", slot)
	}
	if t.transport() == tunnelTransportSSTP {
		return fmt.Errorf("持久 SSTP 出口固定使用已验证端点；请在原始 SSTP 页检测并加入另一个出口")
	}
	if node.HostName == "" {
		return fmt.Errorf("节点不存在，可能节点池已刷新")
	}
	t.changeMu.Lock()
	defer t.changeMu.Unlock()
	if t.Status == "stopped" {
		return fmt.Errorf("Slot 已停止，请先启动")
	}
	if t.Status == "starting" {
		return fmt.Errorf("这个出口正在连接中，稍等一下")
	}
	policy := t.policySnapshot()
	if image := freshCandidateImage(node); image != nil {
		if err := policy.checkImage(*image); err != nil {
			return err
		}
	} else if policy.Country != "" && node.CountryCode != "" && !strings.EqualFold(policy.Country, node.CountryCode) {
		return fmt.Errorf("手动指定节点不满足 Slot 国家策略")
	}
	if m.nodeInUse(node.HostName, slot) {
		return fmt.Errorf("节点已被其他出口占用")
	}
	oldHost := t.Node.HostName
	if oldHost == node.HostName {
		return fmt.Errorf("这个节点已经是当前出口")
	}
	t.rememberSwap(oldHost)
	t.rememberSwap(node.HostName)
	m.reconnectTo(t, oldHost, &node)
	return nil
}

// pickSwapTarget 给"换节点"挑下一个目标，并把该跳过的节点记进历史。
//
// 记两个：换下来的那个，以及刚挑中的这个。挑中的也记是因为真机上踩到过——
// 它连不上时会被候选列表换成别人，但它自己没进历史，
// 于是下次点换节点又从它开始试一遍，白等一轮握手超时。
func (m *Manager) pickSwapTarget(t *Tunnel) (Node, error) {
	avoid := t.swapAvoid()
	picks := m.policyCandidates(t.policySnapshot(), avoid, t.Slot)
	var err error
	if len(picks) == 0 {
		err = fmt.Errorf("没有符合策略的替代候选")
	}
	if err != nil && len(avoid) > 1 {
		// 这个地区的节点都换过一轮了。清掉历史重新开始，
		// 总比告诉用户"没得换了"好——转一圈之后原来那些节点未必还是当初的状态。
		t.forgetSwaps()
		picks = m.policyCandidates(t.policySnapshot(), t.swapAvoid(), t.Slot)
		err = nil
		if len(picks) == 0 {
			err = fmt.Errorf("没有符合策略的替代候选")
		}
	}
	if err != nil {
		return Node{}, err
	}
	t.rememberSwap(t.Node.HostName)
	t.rememberSwap(picks[0].HostName)
	return picks[0], nil
}

// StopAll 停掉所有隧道并清空状态文件。
func (m *Manager) StopAll() {
	for _, t := range m.Tunnels() {
		_ = m.Stop(t.Slot)
	}
}

// SetCred 改一条出口的 SOCKS5 凭据。cred 两个字段都为空表示随机重置。
//
// 改完要通知后端：本机 Xray 的 socks 出站里带着这套凭据，
// 不同步的话面板侧的节点会立刻连不上自己的出口。
func (m *Manager) SetCred(slot int, cred SocksCred) (SocksCred, error) {
	m.mu.RLock()
	t, ok := m.tunnels[slot]
	m.mu.RUnlock()
	if !ok {
		return SocksCred{}, fmt.Errorf("槽位 %d 没有运行中的隧道", slot)
	}

	if cred.User == "" && cred.Pass == "" {
		gen, err := newSocksCred()
		if err != nil {
			return SocksCred{}, err
		}
		cred = gen
	}
	if err := validateCred(cred); err != nil {
		return SocksCred{}, err
	}

	t.changeMu.Lock()
	defer t.changeMu.Unlock()
	if !m.ownsTunnel(t) {
		return SocksCred{}, fmt.Errorf("Slot 已删除")
	}
	t.opMu.Lock()
	defer t.opMu.Unlock()
	previous := t.credential()
	apply := func() error {
		if m.credentialApply != nil {
			return m.credentialApply(t)
		}
		return m.resync(t)
	}
	restore := func(cause error) (SocksCred, error) {
		t.setCredential(previous)
		if err := apply(); err != nil {
			t.blockForPolicy("SOCKS 配置恢复失败，Slot 保持阻断")
			_ = m.saveState()
			return SocksCred{}, fmt.Errorf("凭据修改失败且旧配置无法运行，Slot 已阻断: %w", err)
		}
		return SocksCred{}, fmt.Errorf("凭据修改失败，已恢复旧凭据: %w", cause)
	}
	t.setCredential(cred)
	if err := apply(); err != nil {
		return restore(err)
	}
	if err := m.saveState(); err != nil {
		return restore(err)
	}
	return cred, nil
}

// ReconcileOutbounds 在启动恢复隧道后跑一次，把后端出站对齐到当前隧道（含 SOCKS5 凭据）。
//
// 只为 3x-ui 模式而生：它的 OnTunnelsChanged 是空操作，重启不会重写面板出站，
// 而从旧版本升上来时面板里持久化的 socks 出站没有认证字段，端口一旦要认证就连不上。
// 自建模式恢复时每条隧道 up 都会重建配置，本就自洽，这里跳过免得多重启一次 Xray。
func (m *Manager) ReconcileOutbounds() {
	p, err := openPanel()
	if err != nil || p.Kind() != "3x-ui" {
		return
	}

	// 等隧道尽量都起完再重写一次，避免只覆盖到先 up 的那几条
	deadline := time.Now().Add(90 * time.Second)
	for {
		tunnels := m.Tunnels()
		if len(tunnels) == 0 {
			return
		}
		var up *Tunnel
		settled := true
		for _, t := range tunnels {
			if t.Status == "up" && up == nil {
				up = t
			}
			if t.Status == "starting" {
				settled = false
			}
		}
		if (settled || time.Now().After(deadline)) && up != nil {
			if err := m.resync(up); err != nil {
				log.Printf("启动对账面板出站失败: %v", err)
			}
			return
		}
		if settled || time.Now().After(deadline) {
			return // 全 failed，没有可写的出站
		}
		time.Sleep(2 * time.Second)
	}
}

// syncCred 把新凭据写进后端的 socks 出站。
//
// 两种后端的做法不同：自建模式整份重建配置，3x-ui 模式只改出站那一段。
// 都走 ResyncOutbound，接口语义正好是"重写这条隧道对应的出站"。
func (m *Manager) syncCred(t *Tunnel) {
	if err := m.resync(t); err != nil {
		log.Printf("同步 SOCKS5 凭据到节点链接后端失败: %v", err)
	}
}

// Shutdown 停掉运行态但保留状态文件，让下次启动能恢复同样的隧道。
func (m *Manager) Shutdown() {
	m.shutdownWithStop(func(t *Tunnel) { t.stop() })
}

func (m *Manager) shutdownWithStop(stop func(*Tunnel)) {
	// Fence all writers before the first temporary stopped status. A worker
	// completing another Slot during teardown must not persist half a shutdown
	// as explicit operator stop intent. Wait for an existing commit first.
	m.saveMu.Lock()
	m.shuttingDown = true
	m.saveMu.Unlock()
	for _, t := range m.Tunnels() {
		stop(t)
	}
}

// prepareHost 打开转发开关。netns 出网依赖它。
func prepareHost() error {
	if err := cmdRun(exec.Command("sysctl", "-qw", "net.ipv4.ip_forward=1")); err != nil {
		return fmt.Errorf("开启 ip_forward 失败: %w", err)
	}
	return nil
}

// nodeInUse 判断某节点是否已被别的隧道占用。
func (m *Manager) nodeInUse(host string, exceptSlot int) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	for slot, t := range m.tunnels {
		t.mu.Lock()
		matches := slot != exceptSlot && t.Status != "stopped" && t.Node.HostName == host
		t.mu.Unlock()
		if matches {
			return true
		}
	}
	return false
}

func (m *Manager) ownsTunnel(t *Tunnel) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.tunnels[t.Slot] == t
}

// rebind 在隧道换节点后，把原先指向旧节点的 3x-ui 入站改绑到新节点。
// 面板不可用时静默跳过，健康检查本身不应因此失败。
func (m *Manager) rebind(oldHost string, t *Tunnel) error {
	x, err := openPanel()
	if err != nil {
		return fmt.Errorf("绑定配置后端不可用: %w", err)
	}
	return x.Rebind(oldHost, t, m.Tunnels())
}

// resync 在节点没换但重连过之后，把 3x-ui 的出站配置刷新一遍。
// 面板不可用时静默跳过，健康检查本身不应因此失败。
func (m *Manager) resync(t *Tunnel) error {
	x, err := openPanel()
	if err != nil {
		return fmt.Errorf("出站配置后端不可用: %w", err)
	}
	return x.ResyncOutbound(t, m.Tunnels())
}

// notifyPanel 告诉后端隧道集合变了。
//
// 自建模式下出站是由隧道列表现算出来的，不通知的话新开的出口在 Xray 里
// 没有对应的 socks 出站，绑定会指向一个不存在的 tag。接管 3x-ui 时是空操作。
// 后端不可用不该让开关出口失败，所以只记日志。
func (m *Manager) notifyPanel() {
	p, err := openPanel()
	if err != nil {
		return
	}
	if err := p.OnTunnelsChanged(m.Tunnels()); err != nil {
		log.Printf("同步节点链接后端失败: %v", err)
	}
}
