package main

import (
	"sync"
	"time"
)

const (
	exitSourceStable   = "xnvgatebox_stable"
	exitSourceHome     = "new_residential"
	exitSourceNativeDC = "new_native_datacenter"
)

// ExitInbound 是挂在某个出口上的一个受管入站。
type ExitInbound struct {
	ManagedSlot bool   `json:"managed_slot,omitempty"`
	Manual      bool   `json:"manual,omitempty"`
	HostDirect  bool   `json:"host_direct,omitempty"`
	BoundSlot   int    `json:"bound_slot,omitempty"`
	NameMode    string `json:"name_mode,omitempty"`
	ID          int    `json:"id"`
	Port        int    `json:"port"`
	Remark      string `json:"remark"`
	Protocol    string `json:"protocol"`
	Enable      bool   `json:"enable"`
	Tag         string `json:"tag"`
}

// Exit 是界面上的一行：一条隧道加上挂在它出口的所有入站。
// 用户脑子里的单位是"一个出口"，不是"一条隧道"和"一个入站"两样东西。
type Exit struct {
	Slot              int            `json:"slot"`
	Port              int            `json:"port"` // SOCKS5 端口
	Host              string         `json:"host"`
	Region            string         `json:"region"`
	Country           string         `json:"country"`
	ExitIP            string         `json:"exit_ip"`
	Phase             string         `json:"phase,omitempty"`
	Status            string         `json:"status"`
	Err               string         `json:"err,omitempty"`
	Since             time.Time      `json:"since"`
	Egress            *EgressProfile `json:"egress"`
	Policy            SlotPolicy     `json:"policy"`
	LatencyMS         float64        `json:"latency_ms,omitempty"`
	CanRollbackPolicy bool           `json:"can_rollback_policy"`
	SourceCategory    string         `json:"source_category"`
	SourceName        string         `json:"source_name,omitempty"`
	Native            bool           `json:"native,omitempty"`
	// ProxyAddress/ProxyPort are omitted for the original stable slots, whose
	// SOCKS listener is always loopback. Supplemental verified exits carry an
	// explicit public upstream and never reuse the stable slot namespace.
	ProxyAddress string `json:"proxy_address,omitempty"`
	ProxyPort    int    `json:"proxy_port,omitempty"`
	// SOCKS5 凭据：界面要能看、能复制、能改
	PublicSocks *SocksExposure `json:"public_socks,omitempty"`
	SocksUser   string         `json:"socks_user"`
	SocksPass   string         `json:"socks_pass"`
	Inbounds    []ExitInbound  `json:"inbounds"`
}

// ExitsView 是主界面需要的全部数据。
type ExitsView struct {
	Exits      []Exit        `json:"exits"`
	HostDirect []ExitInbound `json:"host_direct"`
	// Direct 是没绑到任何出口的入站，仍然要能看见，否则用户会以为它们不见了
	Direct []ExitInbound `json:"direct"`
	Panel  string        `json:"panel"` // 面板不可用时的原因，空表示正常
	// Backend 是 "3x-ui" 或 "native"。界面据此决定是否提供新建入站入口：
	// 接管面板时入站归面板管，自建模式才由 fanout 自己建。
	Backend string `json:"backend"`
	// PanelInfo 是后端的一行说明，显示在标题旁
	PanelInfo string `json:"panel_info"`
	// PublicIP 是母机公网 IPv4，前端用它当 SOCKS5/分享链接的连接地址
	PublicIP string `json:"public_ip"`
}

// inboundCache 给入站列表做很短的缓存。界面每几秒轮询一次，
// 而每次读入站都要顺带解析一遍完整的 Xray 配置，没必要每次都真的去问面板。
type inboundCache struct {
	mu   sync.Mutex
	at   time.Time
	list []Inbound
	err  error
}

const inboundCacheTTL = 2500 * time.Millisecond

var ibCache inboundCache

func cachedInbounds(live map[string]bool) ([]Inbound, error) {
	ibCache.mu.Lock()
	defer ibCache.mu.Unlock()
	if time.Since(ibCache.at) < inboundCacheTTL {
		return ibCache.list, ibCache.err
	}

	var list []Inbound
	x, err := openPanel()
	if err == nil {
		list, err = x.Inbounds(live)
	}
	ibCache.at, ibCache.list, ibCache.err = time.Now(), list, err
	return list, err
}

// invalidateInbounds 在写操作之后调用，让下一次读立刻反映改动。
func invalidateInbounds() {
	ibCache.mu.Lock()
	ibCache.at = time.Time{}
	ibCache.mu.Unlock()
}

// ExitsOf 把隧道和入站 join 成界面直接可用的形态。
func (m *Manager) ExitsOf() ExitsView {
	tunnels := m.Tunnels()
	view := ExitsView{Exits: make([]Exit, 0, len(tunnels)), PublicIP: hostPublicIP()}

	// 先填后端类型：入站读取失败时界面仍要知道当前是哪种模式
	if p, err := openPanel(); err == nil {
		view.Backend = p.Kind()
		view.PanelInfo = p.Describe()
	}

	live := map[string]bool{}
	for _, t := range tunnels {
		snapshot := t.snapshot()
		if snapshot.Status == "up" {
			live[sanitizeTag(snapshot.Node.HostName)] = true
			live[slotOutboundTag(snapshot.Slot)] = true
		}
	}

	byHost := map[string]int{}
	bySlot := map[int]int{}
	for i, t := range tunnels {
		snapshot := t.snapshot()
		bySlot[snapshot.Slot] = i
		if snapshot.Node.HostName != "" {
			byHost[sanitizeTag(snapshot.Node.HostName)] = i
		}
		cred := snapshot.Cred
		view.Exits = append(view.Exits, Exit{
			Slot: snapshot.Slot, Port: snapshot.Port, Host: snapshot.Node.HostName,
			Region: snapshot.Node.CountryCode, Country: nodeLabel(snapshot.Node),
			ExitIP: snapshot.ExitIP, Status: snapshot.Status, Phase: snapshot.Phase, Err: snapshot.Err, Since: snapshot.Since,
			Egress: snapshot.Egress,
			Policy: t.policySnapshot(), LatencyMS: snapshot.LatencyMS,
			CanRollbackPolicy: snapshot.CanRollbackPolicy,
			SourceCategory:    exitSourceStable,
			SourceName:        "VPN Gate · xnvgatebox stable",
			SocksUser:         cred.User, SocksPass: cred.Pass,
		})
	}
	// Supplemental exits are file-backed and independent of the tunnel manager.
	// A corrupt/expired optional file never hides or mutates stable exits.
	if extra, err := loadSupplementalExits(m.workDir); err == nil {
		view.Exits = append(view.Exits, extra...)
	}

	if p, err := openPanel(); err == nil {
		if n, ok := p.(*Native); ok {
			exposures := n.socksExposures()
			for i := range view.Exits {
				view.Exits[i].PublicSocks = exposures[view.Exits[i].Slot]
			}
		}
	}
	list, err := cachedInbounds(live)
	if err != nil {
		view.Panel = err.Error()
		return view
	}

	for _, ib := range list {
		row := ExitInbound{
			ID: ib.ID, Port: ib.Port, Remark: ib.Remark,
			Protocol: ib.Protocol, Enable: ib.Enable, Tag: ib.Tag, BoundSlot: ib.BoundSlot, NameMode: ib.NameMode, HostDirect: ib.HostDirect, ManagedSlot: ib.ManagedSlot, Manual: ib.Manual,
		}
		if ib.HostDirect {
			view.HostDirect = append(view.HostDirect, row)
			continue
		}
		if ib.BoundSlot > 0 {
			if i, ok := bySlot[ib.BoundSlot]; ok {
				view.Exits[i].Inbounds = append(view.Exits[i].Inbounds, row)
			} else {
				view.Direct = append(view.Direct, row)
			}
			continue
		}
		if i, ok := byHost[ib.BoundTo]; ib.BoundTo != "" && ok {
			view.Exits[i].Inbounds = append(view.Exits[i].Inbounds, row)
			continue
		}
		view.Direct = append(view.Direct, row)
	}
	return view
}
