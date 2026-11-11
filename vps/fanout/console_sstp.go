package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

type SstpSettings struct {
	Parallelism     int `json:"parallelism"`
	IntervalMinutes int `json:"interval_minutes"`
	ValidMinutes    int `json:"valid_minutes"`
	TimeoutSeconds  int `json:"timeout_seconds"`
}

type sstpState struct {
	Settings    SstpSettings           `json:"settings"`
	Results     map[string]CheckResult `json:"results"`
	LastStarted time.Time              `json:"last_started"`
}

type SstpManager struct {
	mu           sync.Mutex
	c            *Console
	state        sstpState
	job          *CheckRun
	lastAttempts map[string]CheckResult // Session attempts, separate from exportable observations.
	probe        func(context.Context, Node, SstpSettings, func(string)) CheckResult
	dependencies func() error
}

func validateSstpSettings(v SstpSettings) error {
	if err := validateCheckParallelism(v.Parallelism); err != nil {
		return err
	}
	if v.IntervalMinutes < 0 || v.IntervalMinutes > 525600 || v.ValidMinutes < 1 || v.ValidMinutes > 10080 || v.TimeoutSeconds < 10 || v.TimeoutSeconds > 3600 {
		return fmt.Errorf("并发须为正整数；周期 0 表示关闭，有效期 1–10080 分钟，超时 10–3600 秒")
	}
	return nil
}

func (c *Console) loadSstpManager() error {
	s := &SstpManager{c: c, state: sstpState{Settings: SstpSettings{Parallelism: c.checkParallelism, ValidMinutes: 60, TimeoutSeconds: 90}, Results: map[string]CheckResult{}}}
	blob, err := os.ReadFile(filepath.Join(c.m.workDir, "sstp.json"))
	if err == nil {
		if json.Unmarshal(blob, &s.state) != nil || validateSstpSettings(s.state.Settings) != nil {
			return fmt.Errorf("SSTP 设置或结果文件损坏，保留原文件")
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	if s.state.Results == nil {
		s.state.Results = map[string]CheckResult{}
	}
	s.probe = s.probeNode
	s.lastAttempts = map[string]CheckResult{}
	s.dependencies = sstpDependencies
	c.sstp = s
	return nil
}

func (s *SstpManager) persist() error {
	blob, err := json.Marshal(s.state)
	if err != nil {
		return err
	}
	if err = atomicConfigWrite(filepath.Join(s.c.m.workDir, "sstp.json"), blob); err != nil {
		return fmt.Errorf("SSTP 结果或设置保存失败")
	}
	return nil
}

func sstpProfile(n Node) string {
	blob, _ := json.Marshal(struct {
		Host, IP   string
		Candidates []SstpEndpoint
	}{n.HostName, n.IP, n.SSTPCandidates})
	return profileDigest(string(blob))
}

func freshSstpResult(n Node, r CheckResult, now time.Time) CheckResult {
	r.Protocol = "sstp"
	r.Stale = r.CheckedAt.After(now) || !r.ExpiresAt.After(r.CheckedAt) || r.ProfileSHA != sstpProfile(n) || r.CheckedAt.IsZero() || !r.ExpiresAt.After(now)
	if r.Status == "passed" && (!sstpPublicIPv4(r.ActualIP) || r.ObservedBy != "vps" || r.Port < 1 || r.Port > 65535) {
		r.Stale = true
	}
	matched := false
	for _, endpoint := range n.SSTPCandidates {
		if officialSstpEndpoint(n, endpoint) && endpoint.Port == r.Port {
			matched = true
		}
	}
	if r.Status == "passed" && !matched {
		r.Stale = true
	}
	r.Country, r.IPType = "", "unknown"
	if r.Egress != nil {
		image := *r.Egress
		expiry, err := time.Parse(time.RFC3339Nano, image.ExpiresAt)
		if image.Protocol == "sstp" && image.IP == r.ActualIP && image.IntelligenceStatus == "passed" && err == nil && expiry.After(now) && image.Provider != "" && image.QueriedAt != "" && image.RuleVersion != "" {
			r.Country, r.IPType = verifiedProfileCountry(image), image.IPType
		}
		if image.Protocol == "sstp" && image.IP == r.ActualIP {
			r.Country = verifiedProfileCountry(image)
		}
		image.Raw = nil
		r.Egress = &image
	}
	r.CFStatus = "not_tested"
	return r
}

// Reuse the same dispatcher as OpenVPN, but never reuse its connections/evidence.
func (s *SstpManager) start(in CheckRequest) (*CheckRun, error) {
	nodes, _ := s.c.m.Nodes()
	byHost := map[string]Node{}
	for _, n := range nodes {
		if len(n.SSTPCandidates) > 0 {
			byHost[n.HostName] = n
			if in.All {
				in.Hosts = append(in.Hosts, n.HostName)
			}
		}
	}
	items := []CheckResult{}
	seen := map[string]bool{}
	for _, host := range in.Hosts {
		n, ok := byHost[host]
		if !ok {
			return nil, fmt.Errorf("候选不在当前 SSTP 清单中")
		}
		if !seen[host] {
			seen[host] = true
			items = append(items, CheckResult{Host: host, Status: "queued", ProfileSHA: sstpProfile(n), Priority: in.Priority, ObservedBy: "vps", CFStatus: "not_tested"})
		}
	}
	if len(items) == 0 || len(in.Slots) > 0 {
		return nil, fmt.Errorf("请选择 SSTP 候选，不使用出口编号")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.c.ctx.Err() != nil {
		return nil, fmt.Errorf("管理服务正在停止")
	}
	if s.dependencies != nil {
		if err := s.dependencies(); err != nil {
			return nil, err
		}
	}
	if s.job != nil {
		j := s.job
		j.mu.Lock()
		if j.Status == "running" {
			if !in.Priority || j.ctx.Err() != nil {
				j.mu.Unlock()
				return nil, fmt.Errorf("已有 SSTP 检测任务，请等待或取消")
			}
			for _, item := range items {
				found := false
				for i := range j.Items {
					old := &j.Items[i]
					if old.Host == item.Host && (old.Status == "queued" || old.Status == "running") {
						old.Priority = true
						found = true
						break
					}
				}
				if !found {
					j.Items = append(j.Items, item)
					j.Total++
				}
			}
			for host, n := range byHost {
				j.nodes[host] = n
			}
			j.mu.Unlock()
			select {
			case j.wake <- struct{}{}:
			default:
			}
			return j, nil
		}
		// Keep terminal attempts when a new job replaces the previous job. A
		// deferred/cancelled attempt must not turn back into "not tested", or
		// overwrite an earlier measured observation used by private exports.
		for _, result := range j.Items {
			s.lastAttempts[result.Host] = result
		}
		j.mu.Unlock()
	}
	settings := s.state.Settings
	ctx, cancel := context.WithCancel(s.c.ctx)
	j := &CheckRun{ID: randomHex(8), Kind: "sstp", Status: "running", Items: items, Total: len(items), Parallelism: settings.Parallelism, ctx: ctx, cancel: cancel, finished: make(chan struct{}), wake: make(chan struct{}, 1), nodes: byHost}
	before := s.state.LastStarted
	s.state.LastStarted = time.Now().UTC()
	if err := s.persist(); err != nil {
		s.state.LastStarted = before
		cancel()
		return nil, err
	}
	s.job = j
	go dispatchCheckRun(ctx, j, &s.mu, func(index, slot int, item CheckResult, n Node) { s.runItem(ctx, j, index, item, n, settings) })
	return j, nil
}

func (s *SstpManager) runItem(ctx context.Context, j *CheckRun, index int, item CheckResult, n Node, settings SstpSettings) {
	progress := func(phase string) { j.mu.Lock(); j.Items[index].Phase = phase; j.mu.Unlock() }
	r := s.probe(ctx, n, settings, progress)
	r.Host = n.HostName
	r.ProfileSHA = sstpProfile(n)
	r.StartedAt = item.StartedAt
	r.CheckedAt = time.Now().UTC()
	r.ExpiresAt = r.CheckedAt.Add(time.Duration(settings.ValidMinutes) * time.Minute)
	r.Priority = item.Priority
	r.Protocol = "sstp"
	r.ObservedBy = "vps"
	r.CFStatus = "not_tested"
	if ctx.Err() != nil {
		r.Status, r.Code = "cancelled", "cancelled"
	}
	if r.Status == "passed" || r.Status == "failed" {
		s.mu.Lock()
		before, exists := s.state.Results[n.HostName]
		s.state.Results[n.HostName] = r
		if err := s.persist(); err != nil {
			if exists {
				s.state.Results[n.HostName] = before
			} else {
				delete(s.state.Results, n.HostName)
			}
			r.Status, r.Code = "failed", "result_save_failed"
		}
		s.mu.Unlock()
	}
	s.mu.Lock()
	s.lastAttempts[n.HostName] = r
	s.mu.Unlock()
	j.mu.Lock()
	j.Items[index] = r
	j.Done++
	j.mu.Unlock()
}

func (s *SstpManager) shutdown() {
	s.mu.Lock()
	j := s.job
	if j != nil {
		j.cancel()
	}
	s.mu.Unlock()
	if j != nil {
		<-j.finished
	}
}

func (s *SstpManager) watch() {
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-s.c.ctx.Done():
			return
		case now := <-ticker.C:
			s.runScheduled(now)
		}
	}
}

func (s *SstpManager) runScheduled(now time.Time) {
	s.mu.Lock()
	due := s.state.Settings.IntervalMinutes > 0 && now.Sub(s.state.LastStarted) >= time.Duration(s.state.Settings.IntervalMinutes)*time.Minute
	if s.job != nil {
		s.job.mu.Lock()
		due = due && s.job.Status != "running"
		s.job.mu.Unlock()
	}
	s.mu.Unlock()
	if due {
		_, _ = s.start(CheckRequest{All: true})
	}
}

func (s *SstpManager) routes(mux *http.ServeMux) {
	mux.HandleFunc("/api/resources/sstp", s.apiView)
	mux.HandleFunc("/api/resources/sstp/settings", s.apiSettings)
	mux.HandleFunc("/api/resources/sstp/check", func(w http.ResponseWriter, r *http.Request) {
		var in CheckRequest
		if readConsoleJSON(w, r, &in) != nil {
			writeJSON(w, 400, map[string]string{"error": "请求格式无效"})
			return
		}
		j, err := s.start(in)
		if err != nil {
			writeJSON(w, 409, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, 202, j.view())
	})
	mux.HandleFunc("/api/resources/sstp/cancel", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(405)
			return
		}
		s.mu.Lock()
		if s.job != nil {
			s.job.cancel()
		}
		s.mu.Unlock()
		writeJSON(w, 202, map[string]bool{"ok": true})
	})
	mux.HandleFunc("/api/resources/sstp/export", s.apiExport)
	mux.HandleFunc("/api/resources/sstp/promote", s.apiPromote)
}

func (s *SstpManager) apiPromote(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	var in struct {
		Hostname string `json:"hostname"`
	}
	if err := readConsoleJSON(w, r, &in); err != nil || strings.TrimSpace(in.Hostname) == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "请选择一个已通过检测的 SSTP 节点"})
		return
	}
	nodes, _ := s.c.m.Nodes()
	var node Node
	found := false
	for _, candidate := range nodes {
		if candidate.HostName == in.Hostname {
			node, found = candidate, true
			break
		}
	}
	if !found {
		writeJSON(w, http.StatusConflict, map[string]string{"error": "节点已不在当前 SSTP 候选清单中"})
		return
	}
	s.mu.Lock()
	result, ok := s.state.Results[in.Hostname]
	s.mu.Unlock()
	if !ok {
		writeJSON(w, http.StatusConflict, map[string]string{"error": "请先在 VPS 上完成 SSTP 检测"})
		return
	}
	tunnel, err := s.c.m.StartVerifiedSSTP(node, result)
	if err != nil {
		writeJSON(w, http.StatusConflict, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"ok": true, "slot": tunnel.Slot, "status": tunnel.Status})
}

func (s *SstpManager) apiView(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(405)
		return
	}
	nodes, _ := s.c.m.Nodes()
	promoted := map[string]bool{}
	for _, tunnel := range s.c.m.Tunnels() {
		snapshot := tunnel.snapshot()
		if tunnel.transport() == tunnelTransportSSTP && snapshot.Status != "stopped" {
			promoted[snapshot.Node.HostName] = true
		}
	}
	s.mu.Lock()
	settings, last := s.state.Settings, s.state.LastStarted
	attempts := map[string]CheckResult{}
	for host, result := range s.lastAttempts {
		attempts[host] = result
	}
	var job any
	if s.job != nil {
		s.job.mu.Lock()
		for _, result := range s.job.Items {
			attempts[result.Host] = result
		}
		s.job.mu.Unlock()
		job = s.job.view()
	}
	rows := []map[string]any{}
	for _, n := range nodes {
		if len(n.SSTPCandidates) == 0 {
			continue
		}
		result, ok := s.state.Results[n.HostName]
		if ok {
			result = freshSstpResult(n, result, time.Now())
		} else {
			result = CheckResult{Host: n.HostName, Status: "not_tested", IPType: "unknown", CFStatus: "not_tested", ObservedBy: "vps"}
		}
		row := map[string]any{"hostname": n.HostName, "server_ip": n.IP, "source_country": n.CountryCode, "candidates": n.SSTPCandidates, "result": result, "promoted": promoted[n.HostName]}
		if attempt, ok := attempts[n.HostName]; ok && attempt.ProfileSHA == sstpProfile(n) {
			if attempt.Status == "passed" || attempt.Status == "failed" {
				attempt = freshSstpResult(n, attempt, time.Now())
			}
			row["attempt"] = attempt
		}
		rows = append(rows, row)
	}
	s.mu.Unlock()
	dependency := ""
	if s.dependencies != nil {
		if err := s.dependencies(); err != nil {
			dependency = err.Error()
		}
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, 200, map[string]any{"nodes": rows, "settings": settings, "last_started": last, "check": job, "dependency_error": dependency, "cf_status": "not_tested"})
}

func (s *SstpManager) apiSettings(w http.ResponseWriter, r *http.Request) {
	var v SstpSettings
	if err := readConsoleJSON(w, r, &v); err != nil {
		writeJSON(w, 400, map[string]string{"error": err.Error()})
		return
	}
	if err := validateSstpSettings(v); err != nil {
		writeJSON(w, 400, map[string]string{"error": err.Error()})
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.c.ctx.Err() != nil {
		w.WriteHeader(503)
		return
	}
	before := s.state.Settings
	s.state.Settings = v
	if err := s.persist(); err != nil {
		s.state.Settings = before
		writeJSON(w, 500, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, 200, v)
}

func (s *SstpManager) apiExport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(405)
		return
	}
	format := r.URL.Query().Get("format")
	if format != "" && format != "json" && format != "text" {
		http.Error(w, "导出格式无效", 400)
		return
	}
	selected := map[string]bool{}
	if hosts := r.URL.Query().Get("hosts"); hosts != "" {
		for _, host := range strings.Split(hosts, ",") {
			selected[host] = true
		}
	}
	nodes, _ := s.c.m.Nodes()
	rows := []map[string]any{}
	links := []string{}
	now := time.Now().UTC()
	s.mu.Lock()
	for _, n := range nodes {
		if len(selected) > 0 && !selected[n.HostName] {
			continue
		}
		result, ok := s.state.Results[n.HostName]
		if !ok {
			continue
		}
		result = freshSstpResult(n, result, now)
		if result.Status != "passed" || result.Stale {
			continue
		}
		u := &url.URL{Scheme: "sstp", Host: fmt.Sprintf("%s:%d", n.HostName, result.Port), User: url.UserPassword("vpn", "vpn")}
		links = append(links, u.String())
		rows = append(rows, map[string]any{"hostname": n.HostName, "server_ip": n.IP, "port": result.Port, "username": "vpn", "password": "vpn", "source_country": n.CountryCode, "result": result, "uri": u.String()})
	}
	s.mu.Unlock()
	if len(rows) == 0 {
		http.Error(w, "所选范围内没有仍有效的 VPS SSTP 实测结果", 409)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	if format == "text" {
		sort.Strings(links)
		w.Header().Set("Content-Disposition", `attachment; filename="xnvgatebox-sstp.txt"`)
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = w.Write([]byte(strings.Join(links, "\n") + "\n"))
		return
	}
	w.Header().Set("Content-Disposition", `attachment; filename="xnvgatebox-sstp.json"`)
	writeJSON(w, 200, map[string]any{"schema_version": 1, "kind": "vpngate_vps_sstp_observations", "observed_by": "vps", "generated_at": now, "cf_status": "not_tested", "nodes": rows})
}
