package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func consoleFixture(t *testing.T) *Console {
	t.Helper()
	m := NewManager(maximumSlots, t.TempDir())
	c, err := newConsole(m)
	if err != nil {
		t.Fatal(err)
	}
	c.start = func(n Node, p SlotPolicy) (*Tunnel, error) {
		m.mu.Lock()
		defer m.mu.Unlock()
		s, err := m.freeSlot()
		if err != nil {
			return nil, err
		}
		v := &Tunnel{Slot: s, Port: 17927 + s, Node: n, Status: "waiting", Policy: &p, Cred: SocksCred{User: fmt.Sprint(s), Pass: "fixture-only"}}
		m.tunnels[s] = v
		return v, nil
	}
	c.remove = func(s int) error { m.mu.Lock(); defer m.mu.Unlock(); delete(m.tunnels, s); return nil }
	c.ensure = func([]*Tunnel, string) error { return nil }
	t.Cleanup(c.shutdown)
	return c
}

func TestConsoleTargetCapacityWaitingAndPersistence(t *testing.T) {
	c := consoleFixture(t)
	p := ExitPlan{Count: 3, Policy: defaultSlotPolicyForMode("JP", false), ServerName: "fixture.example.invalid"}
	if err := c.applyTarget(p); err != nil {
		t.Fatal(err)
	}
	original := c.m.Tunnels()
	p.Count = 32
	p.Policy.Country = "AQ"
	if err := c.applyTarget(p); err != nil {
		t.Fatal(err)
	}
	if len(c.m.Tunnels()) != 32 {
		t.Fatal("full target not allocated without candidates")
	}
	for i, v := range original {
		if c.m.tunnels[i+1] != v || v.policySnapshot().Country != "JP" {
			t.Fatal("existing identity/policy changed")
		}
	}
	if c.m.tunnels[32].Status != "waiting" || c.m.tunnels[32].policySnapshot().Country != "AQ" {
		t.Fatal("missing country must remain waiting")
	}
	reloaded, err := newConsole(NewManager(32, c.m.workDir))
	if err != nil || reloaded.plan.Count != 32 {
		t.Fatal("target not restored", err)
	}
	p.Count = 3
	if err := c.applyTarget(p); err != nil {
		t.Fatal(err)
	}
	for i, v := range original {
		if c.m.tunnels[i+1] != v {
			t.Fatal("decrease changed retained slots")
		}
	}
	p.Count = maximumSlots + 1
	if c.applyTarget(p) == nil {
		t.Fatal("over limit accepted")
	}
	if c.plan.Count != 3 {
		t.Fatal("invalid plan persisted")
	}
	p.Count = 0
	if err := c.applyTarget(p); err != nil || len(c.m.Tunnels()) != 0 {
		t.Fatal("zero target did not stop allocation", err)
	}
}

func TestConsoleReconcileRetriesBindingFailureWithoutDuplicateAllocation(t *testing.T) {
	c := consoleFixture(t)
	c.ensure = func([]*Tunnel, string) error { return fmt.Errorf("fixture failure") }
	p := ExitPlan{Count: 5, Policy: defaultSlotPolicyForMode("", false)}
	if c.applyTarget(p) == nil || c.plan.Count != 5 || len(c.m.Tunnels()) != 5 {
		t.Fatal("intent lost on partial failure")
	}
	original := c.m.Tunnels()
	c.ensure = func([]*Tunnel, string) error { return nil }
	if err := c.reconcile(); err != nil || c.planError != "" {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(original, c.m.Tunnels()) {
		t.Fatal("retry allocated duplicates")
	}
}

func TestConsoleCorruptPlanFailsClosed(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "console.json"), []byte(`{"count":33}`), 0600)
	if _, err := newConsole(NewManager(32, dir)); err == nil {
		t.Fatal("corrupt plan accepted")
	}
}

func TestConsoleMigrationCheckIncludesPlanAndJournalWithoutMutation(t *testing.T) {
	for _, tc := range []struct{ name, body string }{{"console.json", `{"count":33}`}, {consoleJournal, `{}`}} {
		dir := migrationFixture(t)
		os.WriteFile(filepath.Join(dir, tc.name), []byte(tc.body), 0600)
		before := migrationTree(t, dir)
		report := checkMigrationState(dir, 32, 8899)
		if report.ConfigValid || !reflect.DeepEqual(before, migrationTree(t, dir)) {
			t.Fatal("invalid plan/journal accepted or check mutated files")
		}
	}
}

func TestConsoleInterruptedDeleteRemovesOnlyRequestedSlot(t *testing.T) {
	c := consoleFixture(t)
	p := ExitPlan{Count: 4, Policy: defaultSlotPolicyForMode("", false)}
	if err := c.applyTarget(p); err != nil {
		t.Fatal(err)
	}
	retained := c.m.tunnels[4]
	// Simulate a crash after the explicit Slot 2 deletion intent was committed.
	p.Count = 3
	p.RemoveSlot = 2
	if err := c.savePlan(p); err != nil {
		t.Fatal(err)
	}
	if err := c.reconcile(); err != nil {
		t.Fatal(err)
	}
	if c.m.tunnels[2] != nil || c.m.tunnels[4] != retained || c.plan.RemoveSlot != 0 {
		t.Fatal("interrupted delete removed a different slot")
	}
}

func TestConsoleStableSlotRoutesWaitingAndRemoved(t *testing.T) {
	ib := &nativeInbound{ID: 1, Port: 30032, Protocol: "vless", Enable: true, BoundSlot: 32, BoundTo: "old-host"}
	for _, tc := range []struct {
		slots    []*Tunnel
		route    string
		protocol string
	}{{[]*Tunnel{{Slot: 32, Port: 17959, Status: "waiting"}}, "slot-32", "blackhole"}, {[]*Tunnel{{Slot: 32, Port: 17959, Status: "up", Node: Node{HostName: "new-host"}}}, "slot-32", "socks"}, {nil, "block", "blackhole"}} {
		cfg := buildXrayConfig([]*nativeInbound{ib}, tc.slots)
		rules := cfg["routing"].(map[string]any)["rules"].([]any)
		if rules[0].(map[string]any)["outboundTag"] != tc.route {
			t.Fatal("slot binding lost", rules)
		}
		for _, o := range cfg["outbounds"].([]any) {
			v := o.(map[string]any)
			if v["tag"] == tc.route && v["protocol"] != tc.protocol {
				t.Fatal("unsafe route", v)
			}
		}
	}
}

func TestConsoleMigratesBindingWithoutCredentialChangesOrRepeatedRestart(t *testing.T) {
	n, rt, ts := rollbackFixture(t)
	before, _ := json.Marshal(n.store.Inbounds[0].Clients)
	if err := n.ensureSlotInbounds(ts, "fixture.example.invalid"); err != nil {
		t.Fatal(err)
	}
	after, _ := json.Marshal(n.store.Inbounds[0].Clients)
	if string(before) != string(after) || n.store.Inbounds[0].Port != 30001 || n.store.Inbounds[0].BoundSlot != 1 {
		t.Fatal("migration changed identity")
	}
	restarts := rt.starts
	if err := n.ensureSlotInbounds(ts, "fixture.example.invalid"); err != nil || rt.starts != restarts {
		t.Fatal("unchanged reconciliation restarted Xray", err)
	}
}

func TestConsoleRebindCannotStealArchivedSlotWithReusedHostname(t *testing.T) {
	n, _, ts := rollbackFixture(t)
	n.store.Inbounds[0].BoundSlot = 1
	archived := *n.store.Inbounds[0]
	archived.ID = 2
	archived.Port = 30002
	archived.BoundSlot = 2
	archived.NameMode = "custom"
	archived.Remark = "保留的自定义名称"
	n.store.NextID = 3
	n.store.Inbounds = append(n.store.Inbounds, &archived)
	ts[0].Node.HostName = "replacement"
	if err := n.Rebind("a", ts[0], ts); err != nil {
		t.Fatal(err)
	}
	if n.store.Inbounds[1].BoundSlot != 2 || n.store.Inbounds[1].BoundTo != "a" || n.store.Inbounds[1].Remark != archived.Remark {
		t.Fatal("archived identity stolen by another slot")
	}
	rows, err := n.Inbounds(map[string]bool{"a": true, "slot-01": true})
	if err != nil || rows[1].BoundUp {
		t.Fatal("removed slot displayed as live because hostname was reused")
	}
}

func TestConsoleLegacyMigrationDuringReplacementDoesNotCreateDuplicate(t *testing.T) {
	n, _, ts := rollbackFixture(t)
	second := *n.store.Inbounds[0]
	second.ID = 2
	second.Port = 30002
	second.BoundTo = "b"
	n.store.NextID = 3
	n.store.Inbounds = append(n.store.Inbounds, &second)
	// Slot 1 has begun using the old hostname of Slot 2. Pending previous
	// bindings are authoritative, even before either rebind has completed.
	ts[0].Node.HostName = "b"
	ts[0].setPrevHost("a")
	ts = append(ts, &Tunnel{Slot: 2, Port: 17929, Status: "starting", Node: Node{HostName: "c"}, prevHost: "b"})
	if err := n.ensureSlotInbounds(ts, "fixture.example.invalid"); err != nil {
		t.Fatal(err)
	}
	if len(n.store.Inbounds) != 2 || n.store.NextID != 3 || n.store.Inbounds[0].BoundSlot != 1 || n.store.Inbounds[1].BoundSlot != 2 {
		t.Fatal("replacement duplicated or stole legacy inbounds")
	}
	if n.store.Inbounds[0].Port != 30001 || n.store.Inbounds[0].Clients[0].ID != rollbackFixtureClientID {
		t.Fatal("legacy credentials changed")
	}
}

func TestConsoleSubscriptionActualCountrySelectionCustomNames(t *testing.T) {
	n, _, ts := rollbackFixture(t)
	n.proc = &xrayProc{bin: "fixture-only"}
	jp := "JP"
	ts[0].ExitIP = "192.0.2.1"
	ts[0].acceptExitEvidence(ts[0].ExitIP, ts[0].ExitIP, EgressProfile{Protocol: "openvpn", IP: ts[0].ExitIP, Country: &jp, IntelligenceStatus: "passed", IPType: "unknown", ExpiresAt: time.Now().Add(time.Hour).UTC().Format(time.RFC3339)})
	n.store.Inbounds[0].BoundSlot = 1
	n.store.Inbounds[0].NameMode = ""
	n.store.Inbounds[0].Remark = "slot-01"
	n.store.Inbounds = append(n.store.Inbounds, &nativeInbound{ID: 2, Port: 30002, Protocol: "vless", Enable: true, BoundSlot: 2, Remark: "自定义 🇰🇷", NameMode: "", Clients: []nativeClient{{ID: rollbackFixtureClientID, Enable: true}}}, &nativeInbound{ID: 3, Port: 30003, Protocol: "vless", Enable: true, BoundSlot: 3, Clients: []nativeClient{{ID: rollbackFixtureClientID, Enable: true}}})
	usePanel(t, n)
	m := NewManager(32, t.TempDir())
	m.tunnels[1] = ts[0]
	m.tunnels[2] = &Tunnel{Slot: 2, Status: "up", Node: Node{HostName: "b"}}
	m.tunnels[3] = &Tunnel{Slot: 3, Status: "waiting"}
	links, err := subLinksSelected(m, "fixture.invalid", true, map[int]bool{1: true})
	if err != nil || len(links) != 1 {
		t.Fatal("selection failed", err, len(links))
	}
	u, _ := url.Parse(links[0])
	if u.Fragment != "xnvgatebox稳定 / VPN Gate OpenVPN · 🇯🇵 日本 · 01" || u.User.String() != rollbackFixtureClientID {
		t.Fatal("country/name or credentials incorrect", u.Fragment)
	}
	ibs, err := n.Inbounds(nil)
	if err != nil || ibs[0].NameMode != "auto" {
		t.Fatal("legacy default was exposed as custom in console")
	}
	detail, err := n.InboundDetail(1, "fixture.invalid")
	if err != nil || detail.NameMode != "auto" {
		t.Fatal("legacy default was exposed as custom in connection detail")
	}
	links, err = subLinks(m, "fixture.invalid", true)
	if err != nil || len(links) != 2 {
		t.Fatal("waiting slot leaked", err, len(links))
	}
	u, _ = url.Parse(links[1])
	if u.Fragment != "自定义 🇰🇷 · xnvgatebox稳定 / VPN Gate OpenVPN" {
		t.Fatal("custom name ignored")
	}
	ts[0].Status = "waiting"
	if strings.Contains(subscriptionExitName(m.ExitsOf().Exits[0]), "日本") {
		t.Fatal("unverified country presented as actual")
	}
}

func TestConsoleSelectionAndJSONRejectAmbiguity(t *testing.T) {
	for _, v := range []string{"0", "16385", "1,1", "1,x", "1,", "-1"} {
		if _, err := subscriptionSlots(v); err == nil {
			t.Fatal("invalid selection accepted", v)
		}
	}
	got, err := subscriptionSlots("1,128,16384")
	if err != nil || len(got) != 3 {
		t.Fatal(err)
	}
	for _, body := range []string{`{"count":1,"extra":1}`, `{"count":1} {"count":2}`} {
		r := httptest.NewRequest("POST", "/", strings.NewReader(body))
		var p ExitPlan
		if readConsoleJSON(httptest.NewRecorder(), r, &p) == nil {
			t.Fatal("ambiguous input accepted")
		}
	}
}

func waitConsoleCheck(t *testing.T, j *CheckRun) {
	t.Helper()
	// Large batches fsync every completed observation. Slow CI storage is not
	// a concurrency failure; worker-count assertions remain separate.
	if j.finished != nil {
		select {
		case <-j.finished:
			return
		case <-time.After(30 * time.Second):
			t.Fatal("check queue did not finish persistence and cleanup")
		}
	}
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		j.mu.Lock()
		done := j.Status != "running"
		j.mu.Unlock()
		if done {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("check queue did not finish")
}

func TestConsoleCandidateQueueCancelKeepsCompletedEvidence(t *testing.T) {
	c := consoleFixture(t)
	c.m.nodes = []Node{{HostName: "a", Config: "a"}, {HostName: "b", Config: "b"}}
	started := make(chan struct{}, 2)
	c.results["a"] = CheckResult{Host: "a", Status: "passed"}
	c.probe = func(ctx context.Context, n Node, slot int, progress func(string)) CheckResult {
		started <- struct{}{}
		<-ctx.Done()
		return CheckResult{Host: n.HostName, Status: "cancelled"}
	}
	j, err := c.startCheck(CheckRequest{Kind: "candidates", Hosts: []string{"a", "b"}})
	if err != nil {
		t.Fatal(err)
	}
	<-started
	if _, err := c.startCheck(CheckRequest{Kind: "candidates", Hosts: []string{"b"}}); err == nil {
		t.Fatal("parallel diagnostic accepted")
	}
	j.cancel()
	waitConsoleCheck(t, j)
	if c.results["a"].Status != "passed" || len(c.results) != 1 {
		t.Fatal("cancel overwrote completed evidence")
	}
	if j.Status != "cancelled" || j.Done != 2 || j.Items[1].Status != "cancelled" {
		t.Fatal("queue not cancelled")
	}
}

func TestConsoleRunningCandidateUsesExistingSocksWithoutSecondDial(t *testing.T) {
	c := consoleFixture(t)
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "curl"), []byte("#!/bin/sh\nprintf '192.0.2.202\\n0.01'\n"), 0700)
	t.Setenv("PATH", dir)
	node := Node{HostName: "running", Config: "fixture-profile"}
	c.m.nodes = []Node{node}
	c.m.tunnels[1] = &Tunnel{Slot: 1, Port: 17928, Node: node, Status: "up", ExitIP: "192.0.2.202"}
	c.probe = func(context.Context, Node, int, func(string)) CheckResult {
		t.Error("running candidate dialed a second OpenVPN session")
		return CheckResult{Status: "failed"}
	}
	j, err := c.startCheck(CheckRequest{Kind: "candidates", Hosts: []string{"running"}})
	if err != nil {
		t.Fatal(err)
	}
	waitConsoleCheck(t, j)
	if j.Items[0].Status != "passed" || j.Items[0].Slot != 1 || j.Items[0].ActualIP != "192.0.2.202" {
		t.Fatal("existing SOCKS check not used", j.Items[0].Status, j.Items[0].Code)
	}
}

func TestConsoleShutdownCancelsJobsAndStopsReconciliation(t *testing.T) {
	c := consoleFixture(t)
	c.m.nodes = []Node{{HostName: "cancel-at-stop"}}
	started := make(chan struct{}, 2)
	c.probe = func(ctx context.Context, n Node, slot int, progress func(string)) CheckResult {
		started <- struct{}{}
		<-ctx.Done()
		return CheckResult{Host: n.HostName, Status: "cancelled"}
	}
	job, err := c.startCheck(CheckRequest{Kind: "candidates", Hosts: []string{"cancel-at-stop"}})
	if err != nil {
		t.Fatal(err)
	}
	<-started
	script := filepath.Join(t.TempDir(), "slow.py")
	os.WriteFile(script, []byte("import time;time.sleep(60)\n"), 0600)
	t.Setenv("FANOUT_TOOLBOX_SCRIPT", script)
	c.apiPoolRefresh(httptest.NewRecorder(), httptest.NewRequest("POST", "/", nil))
	watched := make(chan struct{})
	go func() { c.watch(); close(watched) }()
	closed := make(chan struct{})
	go func() { c.shutdown(); close(closed) }()
	select {
	case <-closed:
	case <-time.After(3 * time.Second):
		t.Fatal("shutdown did not wait for bounded cancellation")
	}
	select {
	case <-watched:
	case <-time.After(time.Second):
		t.Fatal("controller continued after shutdown")
	}
	if job.Status != "cancelled" {
		t.Fatal("diagnostic not cancelled at shutdown")
	}
	if c.applyTarget(ExitPlan{Count: 1, Policy: defaultSlotPolicyForMode("", false)}) == nil {
		t.Fatal("quantity allocation accepted after shutdown")
	}
	if _, err := c.startCheck(CheckRequest{Kind: "candidates", Hosts: []string{"cancel-at-stop"}}); err == nil {
		t.Fatal("new diagnostic accepted after shutdown")
	}
}

func TestConsoleDiagnosticCleanupOwnershipIsNarrow(t *testing.T) {
	root := "/var/lib/xnvgatebox/fanout"
	ns := "foabcd240"
	config := root + "/.connectivity-fixture/" + ns + ".ovpn"
	if !diagnosticConfigOwned(root, ns, "/usr/sbin/openvpn", config) {
		t.Fatal("owned diagnostic rejected")
	}
	for _, path := range []string{root + "/" + ns + ".ovpn", root + "/.connectivity-fixture/foabcd1.ovpn", "/tmp/.connectivity-fixture/" + ns + ".ovpn", root + "/.connectivity-fixture/../../" + ns + ".ovpn"} {
		if diagnosticConfigOwned(root, ns, "/usr/sbin/openvpn", path) {
			t.Fatal("foreign process could be killed")
		}
	}
	if diagnosticConfigOwned(root, ns, "/usr/bin/sleep", config) {
		t.Fatal("non-OpenVPN process accepted")
	}
}

func TestConsoleQRLocalPNGAndValidation(t *testing.T) {
	useSettings(t)
	c := consoleFixture(t)
	mux := http.NewServeMux()
	c.routes(mux)
	for _, tc := range []struct {
		path string
		code int
	}{{"/api/console/qr?slots=1,32", 200}, {"/api/console/qr?slots=16385", 400}} {
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, httptest.NewRequest("GET", tc.path, nil))
		if w.Code != tc.code {
			t.Fatal(w.Code)
		}
		if tc.code == 200 && (!strings.HasPrefix(w.Body.String(), "\x89PNG") || w.Header().Get("Cache-Control") != "no-store") {
			t.Fatal("QR not private local PNG")
		}
	}
}

func TestConsoleRefreshFailureRetainsPoolAndSanitizesError(t *testing.T) {
	c := consoleFixture(t)
	usePanel(t, &fakePanel{})
	dir := t.TempDir()
	script := filepath.Join(dir, "failing.py")
	os.WriteFile(script, []byte("raise RuntimeError('fixture-private-value')\n"), 0600)
	pool := filepath.Join(dir, "node_pool.json")
	before := []byte(`{"generated_at":"2026-10-17T00:00:00Z"}`)
	os.WriteFile(pool, before, 0600)
	t.Setenv("FANOUT_TOOLBOX_SCRIPT", script)
	t.Setenv("FANOUT_VALIDATED_POOL_FILE", pool)
	c.m.nodes = []Node{{HostName: "retained"}}
	w := httptest.NewRecorder()
	c.apiPoolRefresh(w, httptest.NewRequest("POST", "/", nil))
	if w.Code != 202 {
		t.Fatal(w.Code)
	}
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		c.refreshMu.Lock()
		done := c.refreshState == "failed"
		c.refreshMu.Unlock()
		if done {
			break
		}
		time.Sleep(time.Millisecond)
	}
	c.refreshMu.Lock()
	failed := c.refreshState == "failed"
	c.refreshMu.Unlock()
	if !failed {
		t.Fatal("failure not reported")
	}
	after, _ := os.ReadFile(pool)
	if string(after) != string(before) || len(c.m.nodes) != 1 || c.m.nodes[0].HostName != "retained" {
		t.Fatal("source failure destroyed previous pool")
	}
	w = httptest.NewRecorder()
	c.apiConsole(w, httptest.NewRequest("GET", "/", nil))
	if strings.Contains(w.Body.String(), "fixture-private-value") || !strings.Contains(w.Body.String(), "pool_refresh_failed_previous_pool_retained") {
		t.Fatal("private process error exposed or missing status")
	}
}
