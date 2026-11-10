package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func writeSupplementalTestManifest(t *testing.T, dir string, mutate func(*supplementalManifest)) {
	t.Helper()
	now := time.Now().UTC()
	m := supplementalManifest{
		SchemaVersion: 1, GeneratedAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Hour),
		Entries: []supplementalEntry{{
			Slot: supplementalSlotBase, SourceName: "verified test source", SourceCategory: exitSourceHome,
			Host: "8.8.8.8", Port: 1080, Country: "US", ExitIP: "1.1.1.1",
			IPType: "strict_residential", LatencyMS: 120,
			CheckedAt: now.Add(-30 * time.Second), ExpiresAt: now.Add(30 * time.Minute),
		}},
	}
	if mutate != nil {
		mutate(&m)
	}
	blob, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, supplementalPoolFile), blob, 0600); err != nil {
		t.Fatal(err)
	}
}

func TestLoadSupplementalResidentialExit(t *testing.T) {
	dir := t.TempDir()
	writeSupplementalTestManifest(t, dir, nil)
	exits, err := loadSupplementalExits(dir)
	if err != nil || len(exits) != 1 {
		t.Fatalf("load: exits=%+v err=%v", exits, err)
	}
	got := exits[0]
	if got.SourceCategory != exitSourceHome || got.ProxyAddress != "8.8.8.8" || got.ProxyPort != 1080 || got.Status != "up" || got.Egress == nil || got.Egress.IPType != "strict_residential" {
		t.Fatalf("unexpected exit: %+v", got)
	}
}

func TestLoadSupplementalNativeDatacenterExit(t *testing.T) {
	dir := t.TempDir()
	writeSupplementalTestManifest(t, dir, func(m *supplementalManifest) {
		m.Entries[0].SourceCategory = exitSourceNativeDC
		m.Entries[0].IPType = "datacenter"
		m.Entries[0].Native = true
	})
	exits, err := loadSupplementalExits(dir)
	if err != nil || len(exits) != 1 || !exits[0].Native {
		t.Fatalf("load native datacenter: exits=%+v err=%v", exits, err)
	}
}

func TestLoadSupplementalRejectsUnverifiedOrUnsafeEntries(t *testing.T) {
	tests := map[string]func(*supplementalManifest){
		"stable category injection": func(m *supplementalManifest) { m.Entries[0].SourceCategory = exitSourceStable },
		"unverified residential":    func(m *supplementalManifest) { m.Entries[0].IPType = "unknown" },
		"false native": func(m *supplementalManifest) {
			m.Entries[0].SourceCategory, m.Entries[0].IPType = exitSourceNativeDC, "datacenter"
		},
		"private proxy":       func(m *supplementalManifest) { m.Entries[0].Host = "127.0.0.1" },
		"ipv6 proxy":          func(m *supplementalManifest) { m.Entries[0].Host = "2001:4860:4860::8888" },
		"hostname proxy":      func(m *supplementalManifest) { m.Entries[0].Host = "proxy.example" },
		"expired evidence":    func(m *supplementalManifest) { m.Entries[0].ExpiresAt = time.Now().Add(-time.Minute) },
		"stable slot overlap": func(m *supplementalManifest) { m.Entries[0].Slot = 1 },
		"half credentials":    func(m *supplementalManifest) { m.Entries[0].Username = "user" },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			writeSupplementalTestManifest(t, dir, mutate)
			if exits, err := loadSupplementalExits(dir); err == nil {
				t.Fatalf("accepted unsafe manifest: %+v", exits)
			}
		})
	}
}

func TestLoadSupplementalRejectsDuplicateSlots(t *testing.T) {
	dir := t.TempDir()
	writeSupplementalTestManifest(t, dir, func(m *supplementalManifest) {
		m.Entries = append(m.Entries, m.Entries[0])
		m.Entries[1].Host = "9.9.9.9"
	})
	if _, err := loadSupplementalExits(dir); err == nil {
		t.Fatal("duplicate slot was accepted")
	}
}

func TestSupplementalFailureCannotReplaceStableExits(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, supplementalPoolFile), []byte("{"), 0600); err != nil {
		t.Fatal(err)
	}
	stable := []Exit{{Slot: 1, SourceCategory: exitSourceStable}}
	if extra, err := loadSupplementalExits(dir); err == nil || extra != nil {
		t.Fatalf("malformed optional pool was accepted: %+v %v", extra, err)
	}
	if len(stable) != 1 || stable[0].SourceCategory != exitSourceStable {
		t.Fatal("stable pool was modified")
	}
}
