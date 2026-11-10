package main

import (
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

type migrationIssue struct {
	File string `json:"file"`
	Code string `json:"code"`
}

type migrationSlot struct {
	Slot                int      `json:"slot"`
	Port                int      `json:"port"`
	Stopped             bool     `json:"stopped"`
	LegacyPolicy        bool     `json:"legacy_policy"`
	Country             string   `json:"country"`
	AllowedIPTypes      []string `json:"allowed_ip_types"`
	GenerateCredentials bool     `json:"generate_credentials_on_start"`
}

type migrationReport struct {
	ConfigValid            bool             `json:"config_valid"`
	Scope                  string           `json:"scope"`
	LiveValidationRequired bool             `json:"live_validation_required"`
	Slots                  []migrationSlot  `json:"slots"`
	InboundCount           int              `json:"inbound_count"`
	Issues                 []migrationIssue `json:"issues"`
}

// Inspect a stopped service's private COPY. No loaders that create credentials,
// recovery writes, subprocesses, sockets, netns or global mutations are used.
// Reports contain only fixed error codes and selected non-secret facts.
func checkMigrationState(dir string, maxSlots, defaultPort int) migrationReport {
	r := migrationReport{Scope: "native_persisted_structure_only", LiveValidationRequired: true,
		Slots: []migrationSlot{}, Issues: []migrationIssue{}}
	issue := func(file, code string) { r.Issues = append(r.Issues, migrationIssue{file, code}) }
	st, err := os.Stat(dir)
	if err != nil || !st.IsDir() {
		issue("directory", "unreadable_directory")
		return r
	}
	// A journal means files may represent different points in a transaction.
	// Do not guess the intended version or perform recovery in a read-only mode.
	for _, name := range []string{managementJournal, stateJournal, nativeJournal, consoleJournal} {
		if _, err := os.Lstat(filepath.Join(dir, name)); err == nil {
			issue(name, "pending_transaction")
		} else if !os.IsNotExist(err) {
			issue(name, "unreadable_file")
		}
	}
	if len(r.Issues) > 0 {
		return r
	}
	read := func(name string, optional bool) ([]byte, bool) {
		path := filepath.Join(dir, name)
		info, err := os.Lstat(path)
		if optional && os.IsNotExist(err) {
			return nil, false
		}
		if err != nil {
			issue(name, "missing_or_unreadable_file")
			return nil, false
		}
		if !info.Mode().IsRegular() || info.Size() > 16<<20 {
			issue(name, "not_a_bounded_regular_file")
			return nil, false
		}
		blob, err := os.ReadFile(path)
		if err != nil {
			issue(name, "unreadable_file")
			return nil, false
		}
		return blob, true
	}
	expectedSlots := false
	if blob, ok := read("console.json", true); ok {
		var plan *ExitPlan
		if json.Unmarshal(blob, &plan) != nil || plan == nil || validateExitPlan(plan, maxSlots) != nil {
			issue("console.json", "invalid_exit_plan")
		} else {
			expectedSlots = plan.Count > 0
		}
	}
	if blob, ok := read("sstp.json", true); ok {
		var state sstpState
		if json.Unmarshal(blob, &state) != nil || validateSstpSettings(state.Settings) != nil {
			issue("sstp.json", "invalid_sstp_settings")
		}
	}
	settings := WebSettings{Port: defaultPort}
	if blob, ok := read("settings.json", false); ok {
		loaded, err := decodeWebSettings(blob, defaultPort)
		if err != nil {
			issue("settings.json", "invalid_settings")
		} else {
			settings = loaded
		}
	}
	if blob, ok := read("password", false); ok && strings.TrimSpace(string(blob)) == "" {
		issue("password", "empty_management_password")
	}
	if blob, ok := read("basepath", false); ok {
		if _, err := validateBasePath(strings.TrimSpace(string(blob))); err != nil {
			issue("basepath", "invalid_base_path")
		}
	}
	stateBlob, hasState := read("state.json", true)
	if blob, ok := stateBlob, hasState; ok {
		var original *persistedState
		if json.Unmarshal(blob, &original) != nil || original == nil {
			issue("state.json", "invalid_state")
		} else if state, err := decodePersistedState(blob, maxSlots, settings.residentialOnly()); err != nil {
			issue("state.json", "invalid_state")
		} else {
			for i, p := range state.Tunnels {
				r.Slots = append(r.Slots, migrationSlot{Slot: p.Slot, Port: p.Port, Stopped: p.Stopped,
					LegacyPolicy: original.Tunnels[i].Policy == nil, Country: p.Policy.Country,
					AllowedIPTypes: p.Policy.AllowedIPTypes, GenerateCredentials: p.SocksUser == ""})
			}
			sort.Slice(r.Slots, func(i, j int) bool { return r.Slots[i].Slot < r.Slots[j].Slot })
		}
	}
	for _, name := range []string{"native.json", "native.previous.json"} {
		if blob, ok := read(name, name == "native.previous.json"); ok {
			store, err := decodeNativeStore(blob)
			if err != nil {
				issue(name, "invalid_native_config")
				continue
			}
			if name == "native.json" {
				r.InboundCount = len(store.Inbounds)
			}
			for _, ib := range store.Inbounds {
				if ib.BoundSlot != 0 || ib.BoundTo != "" || ib.SocksSlot != 0 {
					expectedSlots = true
				}
			}
		}
	}
	// A new direct-only installation has never allocated VPN Gate state.
	// Missing state is acceptable only when no plan or entry refers to a Slot.
	if !hasState && expectedSlots {
		issue("state.json", "missing_slot_state")
	}
	r.ConfigValid = len(r.Issues) == 0
	return r
}

func runMigrationCheck(w io.Writer, dir string, maxSlots, defaultPort int) int {
	report := checkMigrationState(dir, maxSlots, defaultPort)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(report); err != nil || !report.ConfigValid {
		return 1
	}
	return 0
}
