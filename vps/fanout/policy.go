package main

import (
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// SlotPolicy is durable intent, independent of the current backing Node.
// Empty allow lists for ISP/ASN impose no restriction; types are explicit.
type SlotPolicy struct {
	Country          string   `json:"country"`
	AllowedIPTypes   []string `json:"allowed_ip_types"`
	PreferredISP     []string `json:"preferred_isp"`
	AllowedISP       []string `json:"allowed_isp"`
	BlockedISP       []string `json:"blocked_isp"`
	AllowedASN       []string `json:"allowed_asn"`
	BlockedASN       []string `json:"blocked_asn"`
	MaximumLatencyMS int      `json:"maximum_latency_ms"`
}

var policyASN = regexp.MustCompile(`^AS[0-9]+$`)
var policyCountry = regexp.MustCompile(`^[A-Z]{2}$`)
var allIPTypes = []string{"strict_residential", "likely_residential", "mobile", "datacenter", "business_isp", "unknown"}

func defaultSlotPolicy(country string) SlotPolicy {
	return defaultSlotPolicyForMode(country, residentialOnly())
}

func defaultSlotPolicyForMode(country string, residential bool) SlotPolicy {
	types := append([]string(nil), allIPTypes...)
	if residential {
		types = []string{"strict_residential", "likely_residential"}
	}
	return SlotPolicy{Country: strings.ToUpper(strings.TrimSpace(country)), AllowedIPTypes: types}
}

func containsFold(values []string, value string) bool {
	for _, item := range values {
		if strings.EqualFold(item, value) {
			return true
		}
	}
	return false
}

func normalizePolicy(p SlotPolicy) (SlotPolicy, error) {
	p.Country = strings.ToUpper(strings.TrimSpace(p.Country))
	if p.Country != "" && !policyCountry.MatchString(p.Country) {
		return p, fmt.Errorf("国家必须是两位代码或留空")
	}
	if p.MaximumLatencyMS < 0 || p.MaximumLatencyMS > 120000 {
		return p, fmt.Errorf("延迟上限必须为 0..120000 毫秒，0 表示不限")
	}
	lists := []*[]string{&p.AllowedIPTypes, &p.PreferredISP, &p.AllowedISP, &p.BlockedISP, &p.AllowedASN, &p.BlockedASN}
	for i, ptr := range lists {
		if len(*ptr) > 100 {
			return p, fmt.Errorf("策略列表最多 100 项")
		}
		out := make([]string, 0, len(*ptr))
		for _, text := range *ptr {
			value := strings.TrimSpace(text)
			if value == "" || len(value) > 200 || strings.ContainsAny(value, "\r\n\x00") {
				return p, fmt.Errorf("策略列表包含无效值")
			}
			if i == 0 {
				value = strings.ToLower(value)
				if value == "residential" {
					value = "strict_residential"
				}
				if !containsFold(allIPTypes, value) {
					return p, fmt.Errorf("未知 IP 类型: %s", value)
				}
			}
			if i >= 4 {
				value = strings.ToUpper(value)
				if !policyASN.MatchString(value) {
					return p, fmt.Errorf("ASN 必须使用 AS 加数字")
				}
			}
			if !containsFold(out, value) {
				out = append(out, value)
			}
		}
		*ptr = out
	}
	if len(p.AllowedIPTypes) == 0 {
		return p, fmt.Errorf("至少允许一种 IP 类型；unknown 必须显式允许")
	}
	for _, pair := range [][2][]string{{p.AllowedISP, p.BlockedISP}, {p.AllowedASN, p.BlockedASN}} {
		for _, value := range pair[0] {
			if containsFold(pair[1], value) {
				return p, fmt.Errorf("同一值不能同时允许和阻止")
			}
		}
	}
	return p, nil
}

func (t *Tunnel) policySnapshot() SlotPolicy {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.Policy == nil {
		return defaultSlotPolicy(t.Node.CountryCode)
	}
	p := *t.Policy
	p.AllowedIPTypes = append([]string(nil), p.AllowedIPTypes...)
	p.PreferredISP = append([]string(nil), p.PreferredISP...)
	p.AllowedISP = append([]string(nil), p.AllowedISP...)
	p.BlockedISP = append([]string(nil), p.BlockedISP...)
	p.AllowedASN = append([]string(nil), p.AllowedASN...)
	p.BlockedASN = append([]string(nil), p.BlockedASN...)
	return p
}

func stringValue(p *string) string {
	if p == nil {
		return ""
	}
	return strings.TrimSpace(*p)
}

// Country has independent evidence. Type, ISP and ASN still require full
// intelligence; missing fields never prove that an exit avoids a blacklist.
func (p SlotPolicy) checkImage(image EgressProfile) error {
	return p.checkImageForProtocol(image, tunnelTransportOpenVPN)
}

func (p SlotPolicy) checkImageForProtocol(image EgressProfile, protocol string) error {
	if protocol != tunnelTransportOpenVPN && protocol != tunnelTransportSSTP {
		return fmt.Errorf("未知出口协议")
	}
	if image.Protocol != protocol || image.IP == "" {
		return fmt.Errorf("缺少对应 %s 出口画像", strings.ToUpper(protocol))
	}
	if image.IntelligenceStatus == "passed" {
		expiry, err := time.Parse(time.RFC3339Nano, image.ExpiresAt)
		if err != nil || !expiry.After(time.Now()) {
			return fmt.Errorf("画像证据已过期")
		}
	} else if len(p.AllowedISP)+len(p.BlockedISP)+len(p.AllowedASN)+len(p.BlockedASN) > 0 || image.IPType != "unknown" {
		return fmt.Errorf("画像不可用，不能证明满足策略")
	}
	if p.Country != "" && !strings.EqualFold(verifiedProfileCountry(image), p.Country) {
		return fmt.Errorf("实际出口国家不满足 %s", p.Country)
	}
	if !containsFold(p.AllowedIPTypes, image.IPType) {
		return fmt.Errorf("实际出口类型 %s 不在允许列表", image.IPType)
	}
	isp, asn := stringValue(image.ISP), stringValue(image.ASN)
	if len(p.AllowedISP)+len(p.BlockedISP) > 0 && isp == "" {
		return fmt.Errorf("缺少实际出口 ISP 证据")
	}
	if containsFold(p.BlockedISP, isp) || (len(p.AllowedISP) > 0 && !containsFold(p.AllowedISP, isp)) {
		return fmt.Errorf("实际出口 ISP 不满足策略")
	}
	if len(p.AllowedASN)+len(p.BlockedASN) > 0 && asn == "" {
		return fmt.Errorf("缺少实际出口 ASN 证据")
	}
	if containsFold(p.BlockedASN, asn) || (len(p.AllowedASN) > 0 && !containsFold(p.AllowedASN, asn)) {
		return fmt.Errorf("实际出口 ASN 不满足策略")
	}
	return nil
}

func (p SlotPolicy) checkLatency(ms float64) error {
	if math.IsNaN(ms) || math.IsInf(ms, 0) || ms <= 0 {
		return fmt.Errorf("缺少有效的本机 SOCKS 延迟测量")
	}
	if p.MaximumLatencyMS > 0 && ms > float64(p.MaximumLatencyMS) {
		return fmt.Errorf("本机 SOCKS 延迟 %.0f ms 超过上限 %d ms", ms, p.MaximumLatencyMS)
	}
	return nil
}

func freshCandidateImage(n Node) *EgressProfile {
	if n.OpenVPNEgress == nil || n.OpenVPNStatus != "passed" {
		return nil
	}
	image := n.OpenVPNEgress
	expiry, err := time.Parse(time.RFC3339Nano, image.ExpiresAt)
	if err != nil || !expiry.After(time.Now()) || image.IP != n.ExpectedExitIP || image.Protocol != "openvpn" || image.IntelligenceStatus != "passed" {
		return nil
	}
	return image
}

// Initial source country is only a budget hint. Missing/expired live evidence
// remains eligible for probing; no source ping or SSTP label satisfies policy.
func (m *Manager) policyCandidates(p SlotPolicy, avoid map[string]bool, exceptSlot int) []Node {
	m.mu.RLock()
	defer m.mu.RUnlock()
	used := map[string]bool{}
	for slot, t := range m.tunnels {
		t.mu.Lock()
		if slot != exceptSlot && t.Status != "stopped" {
			used[t.Node.HostName] = true
		}
		t.mu.Unlock()
	}
	out := []Node{}
	for _, n := range m.nodes {
		if local, ok := m.localEvidence[n.HostName]; ok && local.Config == n.Config && freshCandidateImage(local) != nil {
			n = local
		}
		if n.HostName == "" || used[n.HostName] || avoid[n.HostName] {
			continue
		}
		image := freshCandidateImage(n)
		if image != nil {
			if p.checkImage(*image) != nil {
				continue
			}
		} else if p.Country != "" && n.CountryCode != "" && !strings.EqualFold(p.Country, n.CountryCode) {
			continue
		}
		out = append(out, n)
	}
	sort.SliceStable(out, func(i, j int) bool {
		ra, la := m.connectivityRank(out[i])
		rb, lb := m.connectivityRank(out[j])
		if ra != rb {
			return ra < rb
		}
		if ra == 0 && la != lb {
			if la <= 0 {
				return false
			}
			if lb <= 0 {
				return true
			}
			return la < lb
		}
		a, b := freshCandidateImage(out[i]), freshCandidateImage(out[j])
		pa, pb := a != nil && containsFold(p.PreferredISP, stringValue(a.ISP)), b != nil && containsFold(p.PreferredISP, stringValue(b.ISP))
		if pa != pb {
			return pa
		}
		return out[i].SpeedMbps > out[j].SpeedMbps
	})
	return out
}

func apiSlotPolicy(m *Manager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		slot, err := strconv.Atoi(r.URL.Query().Get("slot"))
		if err != nil {
			writeJSON(w, 400, map[string]string{"error": "slot 参数无效"})
			return
		}
		if slot == 0 && r.Method == http.MethodGet {
			writeJSON(w, 200, defaultSlotPolicy(""))
			return
		}
		m.mu.RLock()
		t := m.tunnels[slot]
		m.mu.RUnlock()
		if t == nil {
			writeJSON(w, 404, map[string]string{"error": "Slot 不存在"})
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		if r.Method == http.MethodGet {
			writeJSON(w, 200, t.policySnapshot())
			return
		}
		if r.Method != http.MethodPost {
			w.WriteHeader(405)
			return
		}
		p, err := decodeSlotPolicy(w, r)
		if err != nil {
			writeJSON(w, 400, map[string]string{"error": "无效策略 JSON"})
			return
		}
		if err := m.SetSlotPolicy(slot, p); err != nil {
			writeJSON(w, 409, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, 200, map[string]string{"ok": "策略已保存，运行中的 Slot 正在按新策略重新验活"})
	}
}

func decodeSlotPolicy(w http.ResponseWriter, r *http.Request) (SlotPolicy, error) {
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 32768))
	dec.DisallowUnknownFields()
	var p SlotPolicy
	if err := dec.Decode(&p); err != nil {
		return p, err
	}
	var extra interface{}
	if err := dec.Decode(&extra); err != io.EOF {
		return p, fmt.Errorf("必须为一个策略对象")
	}
	return p, nil
}

func apiSlotLifecycle(m *Manager, deleting bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(405)
			return
		}
		slot, err := strconv.Atoi(r.URL.Query().Get("slot"))
		if err != nil {
			writeJSON(w, 400, map[string]string{"error": "slot 参数无效"})
			return
		}
		if deleting {
			err = m.Delete(slot)
		} else {
			err = m.Resume(slot)
		}
		if err != nil {
			writeJSON(w, 409, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, 200, map[string]string{"ok": "Slot 操作已受理"})
	}
}
