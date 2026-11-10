package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	qrcode "github.com/skip2/go-qrcode"
)

const consoleJournal = ".console-transaction.json"

type ExitPlan struct {
	Count      int        `json:"count"`
	Policy     SlotPolicy `json:"policy"`
	ServerName string     `json:"server_name"`
	RemoveSlot int        `json:"remove_slot,omitempty"`
}

type Console struct {
	third            *ThirdPartyManager
	supplemental     *SupplementalManager
	sstp             *SstpManager
	ctx              context.Context
	cancel           context.CancelFunc
	refreshDone      chan struct{}
	m                *Manager
	targetMu         sync.Mutex
	plan             *ExitPlan
	planError        string
	refreshMu        sync.Mutex
	refreshState     string
	refreshAt        string
	refreshError     string
	refreshCause     string
	refreshStarted   time.Time
	sourceMu         sync.Mutex
	poolChanged      chan struct{}
	automation       *automationManager
	checksMu         sync.Mutex
	check            *CheckRun
	results          map[string]CheckResult
	checkParallelism int
	// Test seams exercise intent/persistence without creating real namespaces.
	start  func(Node, SlotPolicy) (*Tunnel, error)
	remove func(int) error
	ensure func([]*Tunnel, string) error
	probe  func(context.Context, Node, int, func(string)) CheckResult
}

func newConsole(m *Manager) (*Console, error) {
	c := &Console{m: m, results: map[string]CheckResult{}, start: m.StartWithPolicy, remove: m.deleteSlot, poolChanged: make(chan struct{}, 1)}
	c.ctx, c.cancel = context.WithCancel(context.Background())
	c.ensure = func(ts []*Tunnel, host string) error {
		p, err := openPanel()
		if err != nil {
			return err
		}
		n, ok := p.(*Native)
		if !ok {
			return fmt.Errorf("自动数量管理仅用于内置 Xray 模式")
		}
		return n.ensureSlotInbounds(ts, host)
	}
	c.probe = c.probeCandidate
	if err := recoverConfigTransaction(m.workDir, consoleJournal, []string{"console.json"}); err != nil {
		return nil, err
	}
	blob, err := os.ReadFile(filepath.Join(m.workDir, "console.json"))
	if err == nil {
		var plan *ExitPlan
		if json.Unmarshal(blob, &plan) != nil || plan == nil {
			return nil, fmt.Errorf("出口计划损坏，保留原文件")
		}
		if err := validateExitPlan(plan, m.maxSlots); err != nil {
			return nil, err
		}
		c.plan = plan
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	// Observations are auxiliary; they never restore a tunnel as healthy.
	if blob, err := os.ReadFile(filepath.Join(m.workDir, "checks.json")); err == nil {
		_ = json.Unmarshal(blob, &c.results)
	}
	if c.results == nil {
		c.results = map[string]CheckResult{}
	}
	for _, r := range c.results {
		m.recordConnectivity(r)
	}
	if err := c.loadCheckSettings(); err != nil {
		return nil, err
	}
	if err := c.loadAutomation(); err != nil {
		c.cancel()
		return nil, err
	}
	if err := c.loadSstpManager(); err != nil {
		c.cancel()
		return nil, err
	}
	c.loadThirdPartyManager()
	c.supplemental = newSupplementalManager(c)
	m.console = c
	return c, nil
}

func validateExitPlan(p *ExitPlan, limit int) error {
	if p.Count < 0 || p.Count > limit || p.Count > maximumSlots {
		return fmt.Errorf("出口数量须为非负整数，不能超过本实例地址/管理员容量 %d", limit)
	}
	if p.Count > 0 {
		if _, _, err := fixedSlotPort(p.Count); err != nil {
			return err
		}
	}
	if p.RemoveSlot < 0 || p.RemoveSlot > limit {
		return fmt.Errorf("待移除出口编号无效")
	}
	policy, err := normalizePolicy(p.Policy)
	if err != nil {
		return err
	}
	p.Policy = policy
	p.ServerName = strings.ToLower(strings.TrimSpace(p.ServerName))
	if p.ServerName == "" {
		p.ServerName = "www.tesla.com"
	}
	if len(p.ServerName) > 253 || !strings.Contains(p.ServerName, ".") || !regexp.MustCompile(`^[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?$`).MatchString(p.ServerName) {
		return fmt.Errorf("REALITY 目标须为有效域名")
	}
	return nil
}

func (c *Console) savePlan(p ExitPlan) error {
	blob, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return err
	}
	tx, err := beginConfigTransaction(c.m.workDir, consoleJournal, []string{"console.json"})
	if err != nil {
		return err
	}
	if err := atomicConfigWrite(filepath.Join(c.m.workDir, "console.json"), blob); err != nil {
		_ = tx.rollback()
		return err
	}
	if err := tx.commit(); err != nil {
		_ = tx.rollback()
		return err
	}
	c.plan = &p
	return nil
}

// Allocate intent immediately, then let bounded workers validate it. Existing
// Slots keep their own policies. Missing candidates remain allocated/waiting.
func (c *Console) applyTarget(p ExitPlan) error {
	// Public target changes cannot inject an internal interrupted deletion.
	p.RemoveSlot = 0
	if err := validateExitPlan(&p, c.m.maxSlots); err != nil {
		return err
	}
	c.targetMu.Lock()
	defer c.targetMu.Unlock()
	if c.ctx.Err() != nil {
		return fmt.Errorf("管理服务正在停止")
	}
	if err := c.savePlan(p); err != nil {
		return fmt.Errorf("无法保存出口计划")
	}
	return c.reconcile()
}

func (c *Console) reconcile() error {
	if c.ctx.Err() != nil {
		return c.ctx.Err()
	}
	if err := c.initializeDefaultTarget(); err != nil {
		c.planError = "default_initialization_failed"
		return err
	}
	if c.plan == nil {
		return nil
	}
	p := *c.plan
	if p.RemoveSlot > 0 {
		for _, t := range c.m.Tunnels() {
			if t.Slot == p.RemoveSlot {
				if err := c.remove(t.Slot); err != nil {
					c.planError = "remove_failed"
					return err
				}
			}
		}
		p.RemoveSlot = 0
		if err := c.savePlan(p); err != nil {
			return err
		}
	}
	ts := c.m.Tunnels()
	sort.Slice(ts, func(i, j int) bool { return ts[i].Slot > ts[j].Slot })
	for len(ts) > p.Count {
		if err := c.remove(ts[0].Slot); err != nil {
			c.planError = "remove_failed"
			return err
		}
		ts = ts[1:]
	}
	for len(c.m.Tunnels()) < p.Count {
		node := Node{CountryCode: p.Policy.Country, Country: p.Policy.Country}
		if candidates := c.m.policyCandidates(p.Policy, nil, 0); len(candidates) > 0 {
			node = candidates[0]
		}
		if _, err := c.start(node, p.Policy); err != nil {
			c.planError = "allocation_failed"
			return err
		}
	}
	if err := c.ensure(c.m.Tunnels(), p.ServerName); err != nil {
		c.planError = "auto_binding_failed"
		return err
	}
	c.planError = ""
	invalidateInbounds()
	return nil
}

func (c *Console) deleteSlot(slot int) error {
	c.targetMu.Lock()
	defer c.targetMu.Unlock()
	c.m.mu.RLock()
	exists := c.m.tunnels[slot] != nil
	c.m.mu.RUnlock()
	if !exists {
		return fmt.Errorf("出口不存在")
	}
	// A final explicit deletion of legacy Slots must not become an untouched
	// instance that the new default would initialize again on the next refresh.
	if c.plan == nil && len(c.m.Tunnels()) == 1 && currentPanelMode() == "native" {
		p := ExitPlan{Count: 0, RemoveSlot: slot, Policy: defaultSlotPolicyForMode("", false)}
		if err := validateExitPlan(&p, c.m.maxSlots); err != nil {
			return err
		}
		if err := c.savePlan(p); err != nil {
			return err
		}
		return c.reconcile()
	}
	// Save the new target before deletion; a crash resumes the explicit decrease.
	if c.plan != nil {
		p := *c.plan
		p.Count = max(0, c.plan.Count-1)
		p.RemoveSlot = slot
		if p.Count < 0 {
			return fmt.Errorf("出口不存在")
		}
		if err := c.savePlan(p); err != nil {
			return err
		}
	}
	if c.plan != nil {
		return c.reconcile()
	}
	return c.m.deleteSlot(slot)
}

func (c *Console) watch() {
	for {
		if c.ctx.Err() != nil {
			return
		}
		c.targetMu.Lock()
		if err := c.reconcile(); err != nil {
			log.Printf("出口计划等待重试: %v", err)
		}
		c.targetMu.Unlock()
		select {
		case <-c.ctx.Done():
			return
		case <-c.poolChanged:
		case <-time.After(15 * time.Second):
		}
	}
}

func readConsoleJSON(w http.ResponseWriter, r *http.Request, v any) error {
	if r.Method != http.MethodPost {
		return fmt.Errorf("只接受 POST")
	}
	d := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8<<20))
	d.DisallowUnknownFields()
	if err := d.Decode(v); err != nil {
		return fmt.Errorf("请求格式无效")
	}
	if d.Decode(new(any)) != io.EOF {
		return fmt.Errorf("只接受一个 JSON 对象")
	}
	return nil
}

func (c *Console) routes(mux *http.ServeMux) {
	c.sstp.routes(mux)
	c.third.routes(mux)
	c.supplemental.routes(mux)
	mux.HandleFunc("/api/console", c.apiConsole)
	mux.HandleFunc("/api/console/target", func(w http.ResponseWriter, r *http.Request) {
		var p ExitPlan
		if err := readConsoleJSON(w, r, &p); err != nil {
			writeJSON(w, 400, map[string]string{"error": err.Error()})
			return
		}
		if panel, err := openPanel(); err != nil || panel.Kind() != "native" {
			writeJSON(w, 409, map[string]string{"error": "自动数量管理仅用于内置 Xray 模式"})
			return
		}
		if err := c.applyTarget(p); err != nil {
			writeJSON(w, 409, map[string]string{"error": firstLine(err.Error())})
			return
		}
		writeJSON(w, 200, map[string]bool{"ok": true})
	})
	mux.HandleFunc("/api/console/direct", c.apiHostDirect)
	mux.HandleFunc("/api/console/socks", c.apiPublicSocks)
	mux.HandleFunc("/api/console/refresh", c.apiPoolRefresh)
	mux.HandleFunc("/api/console/source-settings", c.apiSourceSettings)
	mux.HandleFunc("/api/console/automation", c.apiAutomation)
	mux.HandleFunc("/api/console/check/settings", c.apiCheckSettings)
	mux.HandleFunc("/api/console/check", c.apiCheck)
	mux.HandleFunc("/api/console/check/cancel", c.apiCheckCancel)
	mux.HandleFunc("/api/console/qr", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.WriteHeader(405)
			return
		}
		if _, err := subscriptionSlots(r.URL.Query().Get("slots")); err != nil {
			http.Error(w, "出口选择无效", 400)
			return
		}
		if _, err := subscriptionProxyIDs(r.URL.Query().Get("proxies")); err != nil {
			http.Error(w, "第三方选择无效", 400)
			return
		}
		tok, err := subToken()
		if err != nil {
			http.Error(w, "订阅未就绪", 500)
			return
		}
		link := subFullURL(r, tok)
		if slots := r.URL.Query().Get("slots"); slots != "" {
			link += "&slots=" + slots
		}
		if ids := r.URL.Query().Get("proxies"); ids != "" {
			if r.URL.Query().Get("third") == "0" {
				http.Error(w, "第三方选择无效", 400)
				return
			}
			link += "&proxies=" + ids
		}
		for _, key := range []string{"direct", "vpn", "third"} {
			if v := r.URL.Query().Get(key); v != "" {
				if v != "0" && v != "1" {
					http.Error(w, "订阅范围无效", 400)
					return
				}
				link += "&" + key + "=" + v
			}
		}
		if target := r.URL.Query().Get("target"); target != "" {
			if target != "clash" && target != "mihomo" && target != "base64" && target != "links" {
				http.Error(w, "订阅格式无效", 400)
				return
			}
			link += "&target=" + target
		}
		png, err := qrcode.Encode(link, qrcode.Medium, 256)
		if err != nil {
			http.Error(w, "二维码生成失败", 500)
			return
		}
		w.Header().Set("Content-Type", "image/png")
		w.Header().Set("Cache-Control", "no-store")
		_, _ = w.Write(png)
	})
}

func (c *Console) apiConsole(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(405)
		return
	}
	view := c.m.ExitsOf()
	nodes, fetched := c.m.Nodes()
	ready, stopped := 0, 0
	for _, e := range view.Exits {
		if e.Status == "up" {
			ready++
		}
		if e.Status == "stopped" {
			stopped++
		}
	}
	target := len(view.Exits)
	c.targetMu.Lock()
	plan := c.plan
	planErr := c.planError
	if plan != nil {
		v := *plan
		plan = &v
		target = v.Count
	}
	c.targetMu.Unlock()
	suggestedTarget := defaultExitTarget
	if plan == nil && target > 0 {
		suggestedTarget = target
	}
	c.refreshMu.Lock()
	if c.ctx.Err() != nil {
		c.refreshMu.Unlock()
		w.WriteHeader(503)
		return
	}
	refresh := c.poolRefreshViewLocked()
	c.refreshMu.Unlock()
	c.checksMu.Lock()
	results := make(map[string]CheckResult, len(c.results))
	for k, v := range c.results {
		results[k] = v
	}
	check := c.check
	parallelism := c.checkParallelism
	c.checksMu.Unlock()
	var checkView any
	if check != nil {
		checkView = check.view()
	}
	// Source/profile changes invalidate diagnostic results without calling them
	// currently available. The original completion time is retained in the row.
	for _, n := range nodes {
		if v, ok := results[n.HostName]; ok && (v.ProfileSHA != profileDigest(n.Config) || time.Since(v.CheckedAt) > 15*time.Minute) {
			v.Stale = true
			results[n.HostName] = v
		}
	}
	memory := map[string]int64{}
	if blob, err := os.ReadFile("/proc/meminfo"); err == nil {
		for _, line := range strings.Split(string(blob), "\n") {
			var key string
			var kb int64
			if _, err := fmt.Sscanf(line, "%s %d", &key, &kb); err == nil && (key == "MemTotal:" || key == "MemAvailable:") {
				memory[strings.TrimSuffix(key, ":")] = kb * 1024
			}
		}
	}
	generated := ""
	var pool struct {
		GeneratedAt string             `json:"generated_at"`
		Source      poolSourceMetadata `json:"source"`
	}
	if blob, err := os.ReadFile(envOr("FANOUT_VALIDATED_POOL_FILE", "/var/lib/xnvgatebox/pool/node_pool.json")); err == nil && json.Unmarshal(blob, &pool) == nil {
		generated = pool.GeneratedAt
	}
	serverName := "www.tesla.com"
	if panel, err := openPanel(); err == nil {
		if n, ok := panel.(*Native); ok {
			n.mu.Lock()
			for _, ib := range n.store.Inbounds {
				if ib.Reality != nil && len(ib.Reality.ServerNames) > 0 {
					serverName = ib.Reality.ServerNames[0]
					break
				}
			}
			n.mu.Unlock()
		}
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, 200, map[string]any{"version": version, "capacity": c.m.maxSlots, "target": target, "target_configured": plan != nil, "suggested_target": suggestedTarget, "allocated": len(view.Exits), "ready": ready, "stopped": stopped, "waiting": max(0, target-ready-stopped), "candidates": len(nodes), "pool_read_at": fetched, "pool_generated_at": generated, "pool_source": publicPoolSource(pool.Source), "automation": c.automationView(time.Now().UTC()), "default_server_name": serverName, "plan": plan, "plan_error": planErr, "refresh": refresh, "check": checkView, "check_settings": map[string]int{"parallelism": parallelism}, "results": results, "memory": memory})
}

func (c *Console) apiPoolRefresh(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(405)
		return
	}
	if _, err := c.startPoolRefresh(false); err != nil {
		writeJSON(w, 503, map[string]string{"error": "管理服务正在停止"})
		return
	}
	writeJSON(w, 202, map[string]string{"status": "running"})
}

func (c *Console) startPoolRefresh(scheduled bool) (<-chan struct{}, error) {
	c.refreshMu.Lock()
	if c.ctx.Err() != nil {
		c.refreshMu.Unlock()
		return nil, c.ctx.Err()
	}
	if c.refreshState == "running" {
		done := c.refreshDone
		c.refreshMu.Unlock()
		return done, nil
	}
	c.refreshState, c.refreshError = "running", ""
	c.refreshCause, c.refreshAt = "", ""
	c.refreshStarted = time.Now()
	finished := make(chan struct{})
	c.refreshDone = finished
	c.refreshMu.Unlock()
	log.Print("[pool-refresh] started")
	go func() {
		defer close(finished)
		ctx, cancel := context.WithTimeout(c.ctx, 90*time.Second)
		defer cancel()
		pool := envOr("FANOUT_VALIDATED_POOL_FILE", "/var/lib/xnvgatebox/pool/node_pool.json")
		args := []string{envOr("FANOUT_TOOLBOX_SCRIPT", "/usr/local/lib/xnvgatebox/scripts/toolbox.py"), "--config", envOr("FANOUT_POOL_CONFIG", "/etc/xnvgatebox/pool.json"), "pool", "--output", filepath.Dir(pool), "--schedule-dir", c.m.workDir}
		if scheduled {
			args = append(args, "--scheduled")
		}
		cmd := exec.CommandContext(ctx, "python3", args...)
		var stderr, stdout poolRefreshErrorBuffer
		cmd.Stderr, cmd.Stdout = &stderr, &stdout
		err := cmdRun(cmd)
		cause := poolRefreshCause(ctx, err, string(stderr.data))
		var result struct {
			Status string `json:"status"`
		}
		_ = json.Unmarshal(stdout.data, &result)
		skipped := scheduled && (result.Status == "source_refresh_skipped" || cause == "pool_refresh_busy")
		if err == nil && !skipped {
			_, err = c.m.RefreshNodes()
			if err != nil {
				cause = "pool_refresh_invalid_pool"
			}
		}
		nodes, _ := c.m.Nodes()
		c.refreshMu.Lock()
		defer c.refreshMu.Unlock()
		c.refreshAt = time.Now().UTC().Format(time.RFC3339)
		c.refreshState = "passed"
		if skipped {
			c.refreshState = "skipped"
		} else if err != nil {
			c.refreshState, c.refreshError = "failed", "pool_refresh_failed_previous_pool_retained"
			c.refreshCause = cause
		}
		log.Printf("[pool-refresh] status=%s cause=%s candidates=%d", c.refreshState, c.refreshCause, len(nodes))
	}()
	return finished, nil
}
