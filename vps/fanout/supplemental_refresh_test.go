package main

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestAssignSupplementalSlotsIsStableAndReserved(t *testing.T) {
	a := []supplementalEntry{{Host: "8.8.8.8", Port: 1080}, {Host: "1.1.1.1", Port: 1080}}
	b := []supplementalEntry{{Host: "1.1.1.1", Port: 1080}, {Host: "8.8.8.8", Port: 1080}}
	assignSupplementalSlots(a)
	assignSupplementalSlots(b)
	if a[0].Slot != b[1].Slot || a[1].Slot != b[0].Slot {
		t.Fatalf("endpoint slots changed with ordering: %+v %+v", a, b)
	}
	for _, entry := range a {
		if entry.Slot < supplementalSlotBase || entry.Slot > supplementalSlotMax {
			t.Fatalf("slot outside reserved range: %d", entry.Slot)
		}
	}
}

func TestParseSupplementalCandidate(t *testing.T) {
	for _, value := range []string{"8.8.8.8:1080", "socks5://8.8.8.8:1080"} {
		host, port, ok := parseSupplementalCandidate(value)
		if !ok || host != "8.8.8.8" || port != 1080 {
			t.Fatalf("valid candidate %q rejected: %q %d %v", value, host, port, ok)
		}
	}
	for _, value := range []string{"http://8.8.8.8:1080", "socks5://user:pass@8.8.8.8:1080", "127.0.0.1:1080", "proxy.example:1080", "8.8.8.8:0"} {
		if _, _, ok := parseSupplementalCandidate(value); ok {
			t.Fatalf("unsafe candidate %q accepted", value)
		}
	}
}

func TestSupplementalRefreshPreservesPreviousPoolWhenNoCandidatePasses(t *testing.T) {
	dir := t.TempDir()
	writeSupplementalTestManifest(t, dir, nil)
	path := filepath.Join(dir, supplementalPoolFile)
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	c := &Console{m: NewManager(32, dir)}
	s := newSupplementalManager(c)
	s.fetch = func(context.Context) ([]supplementalCandidate, error) {
		return []supplementalCandidate{{Host: "8.8.8.8", Port: 1080, Source: "test"}}, nil
	}
	s.probe = func(context.Context, ThirdPartyProxy, string) ThirdPartyRecord {
		return ThirdPartyRecord{Status: "failed", IPType: "unknown", CheckedAt: time.Now(), ExpiresAt: time.Now().Add(time.Hour)}
	}
	if _, err := s.refresh(context.Background()); err == nil {
		t.Fatal("empty verified result unexpectedly succeeded")
	}
	after, err := os.ReadFile(path)
	if err != nil || string(after) != string(before) {
		t.Fatal("failed refresh modified the previous active pool")
	}
}

func TestSupplementalRefreshWritesAllVerifiedConnectivityToSSTPPool(t *testing.T) {
	dir := t.TempDir()
	c := &Console{m: NewManager(32, dir)}
	s := newSupplementalManager(c)
	s.fetch = func(context.Context) ([]supplementalCandidate, error) {
		return []supplementalCandidate{
			{Host: "8.8.8.8", Port: 1080, Source: "test residential"},
			{Host: "9.9.9.9", Port: 1080, Source: "test native dc"},
			{Host: "1.0.0.1", Port: 1080, Source: "test unknown"},
		}, nil
	}
	s.probe = func(_ context.Context, p ThirdPartyProxy, _ string) ThirdPartyRecord {
		typeName, native := "unknown", false
		if p.Host == "8.8.8.8" {
			typeName = "strict_residential"
		}
		if p.Host == "9.9.9.9" {
			typeName, native = "datacenter", true
		}
		return ThirdPartyRecord{Status: "passed", ActualIP: p.Host, Country: "US", IPType: typeName, Native: native, CheckedAt: time.Now(), ExpiresAt: time.Now().Add(30 * time.Minute)}
	}
	kept, err := s.refresh(context.Background())
	if err != nil || kept != 3 {
		t.Fatalf("refresh kept=%d err=%v", kept, err)
	}
	exits, err := loadSupplementalExits(dir)
	if err != nil || len(exits) != 3 {
		t.Fatalf("load exits=%+v err=%v", exits, err)
	}
	for _, exit := range exits {
		if exit.SourceCategory != exitSourceSSTP || exit.Egress == nil || exit.Egress.IPType != "unknown" {
			t.Fatalf("supplemental exit was not normalized to the unclassified SSTP pool: %+v", exit)
		}
	}
}

func TestSupplementalDisableCancelsRefreshBeforeRenaming(t *testing.T) {
	dir := t.TempDir()
	writeSupplementalTestManifest(t, dir, nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	c := &Console{m: NewManager(32, dir), ctx: ctx}
	s := &SupplementalManager{c: c}
	s.fetch = func(context.Context) ([]supplementalCandidate, error) {
		return []supplementalCandidate{{Host: "8.8.8.8", Port: 1080, Source: "test"}}, nil
	}
	started := make(chan struct{})
	s.probe = func(ctx context.Context, _ ThirdPartyProxy, _ string) ThirdPartyRecord {
		close(started)
		<-ctx.Done()
		return ThirdPartyRecord{Status: "failed", IPType: "unknown"}
	}
	if !s.start() {
		t.Fatal("refresh did not start")
	}
	<-started
	if err := s.disable(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, supplementalPoolFile)); !os.IsNotExist(err) {
		t.Fatal("active pool was recreated after disable")
	}
	if _, err := os.Stat(filepath.Join(dir, supplementalPoolFile+".disabled")); err != nil {
		t.Fatal("recoverable disabled manifest was not retained")
	}
}
