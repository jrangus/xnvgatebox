package main

import (
	"fmt"
	"net"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode"
)

// Stored only in the private native transaction. List/subscription responses
// expose a redacted view, never this object or the supplier credentials.
type ThirdPartyProxy struct {
	Host      string `json:"host"`
	Port      int    `json:"port"`
	Username  string `json:"username"`
	Password  string `json:"password"`
	Country   string `json:"country"`
	City      string `json:"city"`
	Remark    string `json:"remark"`
	Subscribe bool   `json:"subscribe"`
}

type ThirdPartyRecord struct {
	Status    string    `json:"status"`
	Code      string    `json:"code,omitempty"`
	Digest    string    `json:"digest,omitempty"`
	ActualIP  string    `json:"actual_ip,omitempty"`
	LatencyMS float64   `json:"latency_ms,omitempty"`
	Country   string    `json:"country,omitempty"`
	City      string    `json:"city,omitempty"`
	IPType    string    `json:"ip_type"`
	Native    bool      `json:"native,omitempty"`
	CheckedAt time.Time `json:"checked_at,omitempty"`
	ExpiresAt time.Time `json:"expires_at,omitempty"`
}

func cleanThirdParty(p ThirdPartyProxy) ThirdPartyProxy {
	p.Host = strings.ToLower(strings.Trim(strings.TrimSpace(p.Host), "[]"))
	p.Country = strings.ToUpper(strings.TrimSpace(p.Country))
	p.City, p.Remark = strings.TrimSpace(p.City), strings.TrimSpace(p.Remark)
	return p
}

func safeProxyText(s string, max int) bool {
	if len(s) > max {
		return false
	}
	for _, c := range s {
		if unicode.IsControl(c) {
			return false
		}
	}
	return true
}

func validateThirdParty(p ThirdPartyProxy) error {
	if p.Host == "" || len(p.Host) > 253 || (net.ParseIP(p.Host) == nil && !regexp.MustCompile(`^[a-zA-Z0-9](?:[a-zA-Z0-9.-]*[a-zA-Z0-9])?$`).MatchString(p.Host)) || p.Port < 1 || p.Port > 65535 {
		return fmt.Errorf("请填写服务器域名/IP 和 1–65535 的端口，不含协议或路径")
	}
	if p.Username == "" || p.Password == "" || !safeProxyText(p.Username, 255) || !safeProxyText(p.Password, 255) {
		return fmt.Errorf("SOCKS5 账号和密码不能为空、超过 255 字节或包含控制字符")
	}
	if p.Country != "" && !regexp.MustCompile(`^[A-Z]{2}$`).MatchString(p.Country) {
		return fmt.Errorf("国家须为两位代码，如 US、JP；也可留空")
	}
	if !safeProxyText(p.City, 100) || !safeProxyText(p.Remark, 160) {
		return fmt.Errorf("城市或备注过长或包含控制字符")
	}
	return nil
}

func thirdPartyBound(ib *nativeInbound) bool {
	return ib.ThirdParty != nil && ib.BoundSlot == 0 && ib.BoundTo == "" && !ib.HostDirect && ib.SocksSlot == 0
}
func thirdPartyTag(id int) string { return fmt.Sprintf("third-party-%d", id) }
func thirdPartyDigest(p ThirdPartyProxy) string {
	return profileDigest(fmt.Sprintf("%q:%d:%q:%q", p.Host, p.Port, p.Username, p.Password))
}

func thirdPartyRecord(p ThirdPartyProxy, r ThirdPartyRecord) ThirdPartyRecord {
	if r.Digest != thirdPartyDigest(p) {
		return ThirdPartyRecord{Status: "not_tested", IPType: "unknown"}
	}
	if r.Status == "passed" && !sstpPublicIPv4(r.ActualIP) {
		return ThirdPartyRecord{Status: "not_tested", IPType: "unknown"}
	}
	if r.IPType == "" {
		r.IPType = "unknown"
	}
	if r.CheckedAt.After(time.Now()) || !r.ExpiresAt.After(time.Now()) {
		if r.Status == "passed" {
			r.Status = "expired"
		}
		r.Country, r.City, r.IPType, r.Native = "", "", "unknown", false
	}
	r.Digest = ""
	return r
}

func thirdPartyName(id int, p ThirdPartyProxy, r ThirdPartyRecord) string {
	r = thirdPartyRecord(p, r)
	code, city, manual := r.Country, r.City, false
	if code == "" {
		code, manual = p.Country, p.Country != ""
	}
	if city == "" && (r.Country == "" || p.Country == "" || p.Country == r.Country) {
		city = p.City
		manual = manual || city != ""
	}
	place := countryLabel(code, "")
	if place == "" {
		place = "地区待验证"
	}
	if city != "" {
		place += " · " + city
	}
	if manual {
		place += "（手动标注）"
	}
	label := p.Remark
	if label == "" {
		label = fmt.Sprintf("第三方 · %02d", id)
	}
	return place + " · " + label
}

func (n *Native) thirdPartySnapshot(id int) (*nativeInbound, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	ib := cloneNativeStore(n.store).byID(id)
	if ib == nil || !thirdPartyBound(ib) {
		return nil, fmt.Errorf("第三方代理不存在")
	}
	return ib, nil
}

func (n *Native) setThirdPartyFlag(id int, field string, value bool, tunnels []*Tunnel) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	finish := n.beginChange()
	defer finish()
	ib := n.store.byID(id)
	if ib == nil || !thirdPartyBound(ib) {
		return fmt.Errorf("第三方代理不存在")
	}
	if field == "subscribe" {
		ib.ThirdParty.Subscribe = value
	} else {
		ib.Enable = value
	}
	return n.apply(tunnels)
}

func (n *Native) saveThirdParty(id int, p ThirdPartyProxy, enabled bool, serverName string, tunnels []*Tunnel) (int, error) {
	p = cleanThirdParty(p)
	if err := validateThirdParty(p); err != nil {
		return 0, err
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	finish := n.beginChange()
	defer finish()
	ib := n.store.byID(id)
	if id != 0 && (ib == nil || !thirdPartyBound(ib)) {
		return 0, fmt.Errorf("第三方代理不存在")
	}
	if id == 0 {
		used := n.store.usedPorts()
		for _, t := range tunnels {
			used[t.Port] = true
		}
		var err error
		ib, err = n.prepareInbound(NewInboundSpec{Protocol: "vless", Network: "tcp", Security: "reality", Vision: true, Remark: "第三方 SOCKS5", Dest: serverName + ":443", ServerNames: serverName, Fingerprint: "chrome"}, used)
		if err != nil {
			return 0, fmt.Errorf("无法创建加密接入，请核对 REALITY 目标和可用端口")
		}
		n.store.NextID++
		n.store.Inbounds = append(n.store.Inbounds, ib)
	}
	ib.ThirdParty, ib.Enable, ib.NameMode = &p, enabled, "custom"
	ib.Remark = thirdPartyName(ib.ID, p, ThirdPartyRecord{})
	if err := n.apply(tunnels); err != nil {
		return 0, fmt.Errorf("保存第三方代理失败，已保留原配置")
	}
	return ib.ID, nil
}

func (n *Native) thirdPartyLinks(host string, selected map[int]bool, records map[int]ThirdPartyRecord, names map[string]bool) ([]string, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.unavailable {
		return nil, fmt.Errorf("配置恢复未完成，订阅服务已阻断")
	}
	out := []string{}
	inbounds := append([]*nativeInbound(nil), n.store.Inbounds...)
	sort.Slice(inbounds, func(i, j int) bool { return inbounds[i].ID < inbounds[j].ID })
	for _, ib := range inbounds {
		if !thirdPartyBound(ib) || !ib.Enable || !ib.ThirdParty.Subscribe || (selected != nil && !selected[ib.ID]) {
			continue
		}
		for _, c := range ib.Clients {
			if !c.Enable {
				continue
			}
			u, err := url.Parse(shareLink(ib, c, host))
			if err != nil {
				return nil, fmt.Errorf("第三方节点链接无效")
			}
			u.Fragment = uniqueRemark(thirdPartyName(ib.ID, *ib.ThirdParty, records[ib.ID]), names)
			u.RawFragment = ""
			names[u.Fragment] = true
			out = append(out, u.String())
		}
	}
	return out, nil
}
