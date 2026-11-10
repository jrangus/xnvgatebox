package main

import (
	"bytes"
	"encoding/json"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func migrationFixture(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	files, err := os.ReadDir("testdata/migration-v031")
	if err != nil {
		t.Fatal(err)
	}
	for _, file := range files {
		blob, err := os.ReadFile(filepath.Join("testdata/migration-v031", file.Name()))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, file.Name()), blob, 0600); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func migrationTree(t *testing.T, dir string) map[string]string {
	t.Helper()
	snapshot := map[string]string{}
	err := filepath.WalkDir(dir, func(path string, entry fs.DirEntry, err error) error {
		if err != nil || entry.IsDir() {
			return err
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		blob, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		snapshot[path] = string(blob) + info.Mode().String() + info.ModTime().String()
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return snapshot
}

func TestMigrationCheckV031ThreeSlotsReadOnlyAndRedacted(t *testing.T) {
	t.Setenv("FANOUT_RESIDENTIAL_ONLY", "")
	withResidentialOnly(t, boolPtr(true)) // checker must use copied settings, not globals
	dir := migrationFixture(t)
	before := migrationTree(t, dir)
	settings := getWebSettings()
	var output bytes.Buffer
	if runMigrationCheck(&output, dir, 3, 8899) != 0 {
		t.Fatal("synthetic v0.3.1 snapshot rejected")
	}
	var report migrationReport
	if err := json.Unmarshal(output.Bytes(), &report); err != nil {
		t.Fatal(err)
	}
	if !report.ConfigValid || !report.LiveValidationRequired || report.InboundCount != 3 || len(report.Slots) != 3 {
		t.Fatal("incorrect offline scope or snapshot summary")
	}
	for i, slot := range report.Slots {
		if slot.Slot != i+1 || slot.Port != 17928+i || !slot.LegacyPolicy || slot.GenerateCredentials || !containsFold(slot.AllowedIPTypes, "unknown") {
			t.Fatal("migration changed fixed identity, credentials or copied defaults")
		}
	}
	for _, private := range []string{"fixture-node", "fixture-profile", "fixture-user", "fixture-pass", "fixture-client", "fixture-subscription", "fixture-management", "fixture-entry", "private_key", "public_key", "12345678-1234"} {
		if strings.Contains(output.String(), private) {
			t.Fatalf("report exposed private field %q", private)
		}
	}
	if !reflect.DeepEqual(before, migrationTree(t, dir)) || !reflect.DeepEqual(settings, getWebSettings()) {
		t.Fatal("read-only check modified files or global settings")
	}
}

func TestMigrationMissingStateOnlyAcceptsInstallationsWithoutSlots(t *testing.T) {
	for _, bound := range []bool{false, true} {
		dir := migrationFixture(t)
		os.Remove(filepath.Join(dir, "state.json"))
		if !bound {
			os.WriteFile(filepath.Join(dir, "native.json"), []byte(`{"next_id":1,"inbounds":[]}`), 0600)
			os.Remove(filepath.Join(dir, "native.previous.json"))
		}
		before := migrationTree(t, dir)
		report := checkMigrationState(dir, 32, 8899)
		if report.ConfigValid == bound || !reflect.DeepEqual(before, migrationTree(t, dir)) {
			t.Fatalf("missing state handling: bound=%v, report=%+v", bound, report)
		}
	}
}

func TestMigrationAcceptsFreshInstallBeforeSubscriptionTokenIsCreated(t *testing.T) {
	dir := migrationFixture(t)
	os.Remove(filepath.Join(dir, "state.json"))
	os.Remove(filepath.Join(dir, "native.previous.json"))
	if err := os.WriteFile(filepath.Join(dir, "native.json"), []byte(`{"next_id":1,"inbounds":[]}`), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "settings.json"), []byte(`{"port":8899,"listen_addr":"0.0.0.0","residential_only":false}`), 0600); err != nil {
		t.Fatal(err)
	}
	report := checkMigrationState(dir, 32, 8899)
	if !report.ConfigValid {
		t.Fatalf("fresh install without a lazily-created subscription token must remain upgradeable: %+v", report)
	}
}

func TestMigrationV031PreparationPreservesBindingsWithoutRevivingHealth(t *testing.T) {
	dir := migrationFixture(t)
	blob, _ := os.ReadFile(statePath(dir))
	state, err := decodePersistedState(blob, 3, false)
	if err != nil {
		t.Fatal(err)
	}
	tunnels, err := prepareRestoredTunnels(state, []Node{{HostName: "fixture-node-1", Config: "fresh-pool-profile"}})
	if err != nil {
		t.Fatal(err)
	}
	for i, tn := range tunnels {
		original := state.Tunnels[i]
		if tn.Slot != original.Slot || tn.Port != original.Port || tn.Cred.User != original.SocksUser || tn.Cred.Pass != original.SocksPass || tn.Status != "starting" || tn.egressSnapshot(false) != nil {
			t.Fatal("migration lost identity/credentials or revived old healthy state")
		}
		want := original.PrevHost
		if want == "" {
			want = original.HostName
		}
		if tn.prevHostOf() != want {
			t.Fatal("migration lost unfinished or clean-shutdown binding")
		}
	}
	if tunnels[0].Node.Config != "fresh-pool-profile" || tunnels[2].Node.Config != "fixture-profile-3" {
		t.Fatal("migration ignored fresh pool or missing-node fallback")
	}
	store, err := loadNativeStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	before, _ := json.Marshal(store)
	config := buildXrayConfig(store.sorted(), tunnels)
	after, _ := json.Marshal(store)
	if !bytes.Equal(before, after) {
		t.Fatal("configuration generation changed client UUID or REALITY keys")
	}
	for _, raw := range config["outbounds"].([]any) {
		if raw.(map[string]any)["protocol"] != "blackhole" {
			t.Fatal("restored Slot became routable before live verification")
		}
	}
	// Real pinned parser, static only; the fixture's REALITY destination is a
	// literal loopback address so no external resolution is needed.
	bin, _ := filepath.Abs("../../tools/bin/xray")
	if _, err := os.Stat(bin); os.IsNotExist(err) {
		t.Skip("pinned Xray missing; structural migration checks above completed")
	}
	path, err := writeXrayConfig(t.TempDir(), config)
	if err != nil {
		t.Fatal(err)
	}
	if output, err := exec.Command(bin, "run", "-test", "-c", path).CombinedOutput(); err != nil {
		t.Fatalf("synthetic migrated REALITY config failed static parsing: %s", output)
	}
}

func TestMigrationRejectsInvalidStateBeforePublishingAnySlots(t *testing.T) {
	cases := map[string]string{
		"null":              `null`,
		"partial-user":      `{"tunnels":[{"slot":1,"port":17928,"stopped":true},{"slot":2,"port":17929,"socks_user":"fixture-kept-user","stopped":true}]}`,
		"partial-pass":      `{"tunnels":[{"slot":1,"port":17928,"socks_pass":"fixture-kept-pass","stopped":true}]}`,
		"bad-pair":          `{"tunnels":[{"slot":1,"port":17928,"socks_user":"bad user","socks_pass":"fixture-pass","stopped":true}]}`,
		"duplicate-deleted": `{"tunnels":[],"deleted_slots":[2,2]}`,
		"late-bad-deleted":  `{"tunnels":[{"slot":1,"port":17928,"stopped":true}],"deleted_slots":[2,4]}`,
		"occupied-deleted":  `{"tunnels":[{"slot":1,"port":17928,"stopped":true}],"deleted_slots":[1]}`,
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			dir := migrationFixture(t)
			if err := os.WriteFile(statePath(dir), []byte(body), 0600); err != nil {
				t.Fatal(err)
			}
			before := migrationTree(t, dir)
			m := NewManager(3, dir)
			if _, err := m.restoreState(); err == nil || len(m.tunnels) != 0 || len(m.deletedSlots) != 0 {
				t.Fatal("invalid migration partially populated manager")
			}
			if checkMigrationState(dir, 3, 8899).ConfigValid || !reflect.DeepEqual(before, migrationTree(t, dir)) {
				t.Fatal("checker disagreed with restore or modified bad input")
			}
		})
	}
}

func TestMigrationLegacyDefaultsAndMissingCredentialPair(t *testing.T) {
	for _, strict := range []bool{false, true} {
		state, err := decodePersistedState([]byte(`{"tunnels":[{"slot":1,"port":17928,"stopped":true,"country_code":"jp"}]}`), 3, strict)
		if err != nil {
			t.Fatal(err)
		}
		if state.Tunnels[0].Policy.Country != "JP" || containsFold(state.Tunnels[0].Policy.AllowedIPTypes, "unknown") == strict {
			t.Fatal("legacy policy ignored saved defaults")
		}
		tunnels, err := prepareRestoredTunnels(state, nil)
		if err != nil || validateCred(tunnels[0].Cred) != nil || tunnels[0].Status != "stopped" {
			t.Fatal("complete legacy omission did not receive valid private credentials")
		}
	}
}

func TestMigrationCheckPendingTransactionsRemainUntouched(t *testing.T) {
	for _, name := range []string{nativeJournal, managementJournal, stateJournal} {
		t.Run(name, func(t *testing.T) {
			dir := migrationFixture(t)
			if err := os.WriteFile(filepath.Join(dir, name), []byte("fixture-incomplete-journal"), 0600); err != nil {
				t.Fatal(err)
			}
			before := migrationTree(t, dir)
			var output bytes.Buffer
			if runMigrationCheck(&output, dir, 3, 8899) != 1 || !strings.Contains(output.String(), "pending_transaction") || strings.Contains(output.String(), "fixture-incomplete") {
				t.Fatal("pending journal was ignored or exposed")
			}
			if !reflect.DeepEqual(before, migrationTree(t, dir)) {
				t.Fatal("read-only command performed transaction recovery")
			}
		})
	}
}

func TestMigrationCheckMissingDirectoryDoesNotCreateIt(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "not-created")
	var output bytes.Buffer
	if runMigrationCheck(&output, dir, 3, 8899) != 1 {
		t.Fatal("missing snapshot accepted")
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) || strings.Contains(output.String(), dir) {
		t.Fatal("checker created directory or exposed filesystem path")
	}
}

func TestMigrationCheckInvalidFilesDoNotLeakValues(t *testing.T) {
	for _, tc := range []struct{ file, content string }{
		{"settings.json", "null"},
		{"settings.json", `{"port":-1,"sub_token":"fixture-private-token"}`},
		{"password", "\n"},
		{"basepath", "fixture-private-entry/forbidden"},
		{"native.json", "null"},
		{"native.json", `{"next_id":2,"inbounds":[null]}`},
		{"native.previous.json", `{"next_id":1,"inbounds":[{"id":1,"port":30001}]}`},
	} {
		t.Run(tc.file+tc.content, func(t *testing.T) {
			dir := migrationFixture(t)
			if err := os.WriteFile(filepath.Join(dir, tc.file), []byte(tc.content), 0600); err != nil {
				t.Fatal(err)
			}
			var output bytes.Buffer
			if runMigrationCheck(&output, dir, 3, 8899) != 1 || strings.Contains(output.String(), "fixture-private") {
				t.Fatal("invalid file accepted or private value included")
			}
		})
	}
}

func TestMigrationStartupRejectsCorruptAccessAndNativeConfig(t *testing.T) {
	for _, tc := range []struct{ file, content string }{
		{"settings.json", "null"},
		{"settings.json", `{"port":-1}`},
		{"settings.json", `{"port":8899,"listen_addr":"invalid-host"}`},
		{"password", "\n"},
		{"basepath", "invalid/path"},
		{"native.json", "null"},
	} {
		t.Run(tc.file+tc.content, func(t *testing.T) {
			dir := migrationFixture(t)
			if err := os.WriteFile(filepath.Join(dir, tc.file), []byte(tc.content), 0600); err != nil {
				t.Fatal(err)
			}
			before := migrationTree(t, dir)
			var err error
			switch tc.file {
			case "settings.json":
				blob, _ := os.ReadFile(filepath.Join(dir, tc.file))
				_, err = decodeWebSettings(blob, 8899)
			case "password":
				_, _, err = NewAuth(dir)
			case "basepath":
				_, _, err = LoadBasePath(dir)
			case "native.json":
				_, err = loadNativeStore(dir)
			}
			if err == nil || !reflect.DeepEqual(before, migrationTree(t, dir)) {
				t.Fatal("corrupt persisted configuration was accepted or replaced")
			}
		})
	}
	n, runtime, tunnels := rollbackFixture(t)
	if err := os.WriteFile(filepath.Join(n.dir, "native.previous.json"), []byte("null"), 0600); err != nil {
		t.Fatal(err)
	}
	if n.Rollback(tunnels) == nil || runtime.starts != 0 || runtime.stops != 0 {
		t.Fatal("null history replaced a working native configuration")
	}
	assertAcceptedNative(t, n)
}

func TestMigrationCheckRejectsLinkedAndMissingFiles(t *testing.T) {
	for _, linked := range []bool{false, true} {
		dir := migrationFixture(t)
		if err := os.Remove(filepath.Join(dir, "password")); err != nil {
			t.Fatal(err)
		}
		if linked {
			external := filepath.Join(t.TempDir(), "fixture-private-password")
			if err := os.WriteFile(external, []byte("fixture-external-secret"), 0600); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(external, filepath.Join(dir, "password")); err != nil {
				t.Fatal(err)
			}
		}
		var output bytes.Buffer
		if runMigrationCheck(&output, dir, 3, 8899) != 1 || strings.Contains(output.String(), "fixture-external") {
			t.Fatal("missing/linked snapshot file accepted or external content exposed")
		}
	}
}
