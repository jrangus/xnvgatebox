package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	supplementalPoolFile    = "supplemental-exits.json"
	supplementalPoolMaxSize = 2 << 20
	supplementalSlotBase    = 100000
	supplementalSlotMax     = 999999
)

type supplementalManifest struct {
	SchemaVersion int                 `json:"schema_version"`
	GeneratedAt   time.Time           `json:"generated_at"`
	ExpiresAt     time.Time           `json:"expires_at"`
	Entries       []supplementalEntry `json:"entries"`
}

type supplementalEntry struct {
	Slot           int       `json:"slot"`
	SourceName     string    `json:"source_name"`
	SourceCategory string    `json:"source_category"`
	Host           string    `json:"host"`
	Port           int       `json:"port"`
	Username       string    `json:"username,omitempty"`
	Password       string    `json:"password,omitempty"`
	Country        string    `json:"country"`
	City           string    `json:"city,omitempty"`
	ExitIP         string    `json:"exit_ip"`
	IPType         string    `json:"ip_type"`
	Native         bool      `json:"native,omitempty"`
	LatencyMS      float64   `json:"latency_ms,omitempty"`
	CheckedAt      time.Time `json:"checked_at"`
	ExpiresAt      time.Time `json:"expires_at"`
}

// loadSupplementalExits loads only recently measured SOCKS5 exits. The file is
// optional and deliberately independent from tunnel state: failure here can
// never remove or mutate the original xnvgatebox stable slots.
func loadSupplementalExits(workDir string) ([]Exit, error) {
	path := filepath.Join(workDir, supplementalPoolFile)
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() < 2 || info.Size() > supplementalPoolMaxSize {
		return nil, errors.New("invalid supplemental exit manifest file")
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	decoder := json.NewDecoder(io.LimitReader(f, supplementalPoolMaxSize+1))
	decoder.DisallowUnknownFields()
	var manifest supplementalManifest
	if err := decoder.Decode(&manifest); err != nil {
		return nil, fmt.Errorf("decode supplemental exit manifest: %w", err)
	}
	if err := ensureJSONEOF(decoder); err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	if manifest.SchemaVersion != 1 || manifest.GeneratedAt.IsZero() || manifest.ExpiresAt.IsZero() ||
		manifest.GeneratedAt.After(now.Add(5*time.Minute)) || !manifest.ExpiresAt.After(now) ||
		!manifest.ExpiresAt.After(manifest.GeneratedAt) {
		return nil, errors.New("supplemental exit manifest is stale or invalid")
	}
	if len(manifest.Entries) > 512 {
		return nil, errors.New("supplemental exit manifest has too many entries")
	}
	seenSlots := make(map[int]bool, len(manifest.Entries))
	seenEndpoints := make(map[string]bool, len(manifest.Entries))
	exits := make([]Exit, 0, len(manifest.Entries))
	for i, entry := range manifest.Entries {
		exit, err := normalizeSupplementalEntry(entry, manifest, now)
		if err != nil {
			return nil, fmt.Errorf("supplemental entry %d: %w", i, err)
		}
		endpoint := net.JoinHostPort(exit.ProxyAddress, fmt.Sprint(exit.ProxyPort))
		if seenSlots[exit.Slot] || seenEndpoints[endpoint] {
			return nil, errors.New("supplemental exit manifest contains duplicate slot or endpoint")
		}
		seenSlots[exit.Slot], seenEndpoints[endpoint] = true, true
		exits = append(exits, exit)
	}
	return exits, nil
}

func ensureJSONEOF(decoder *json.Decoder) error {
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		if err == nil {
			return errors.New("supplemental exit manifest contains trailing JSON")
		}
		return err
	}
	return nil
}

func normalizeSupplementalEntry(entry supplementalEntry, manifest supplementalManifest, now time.Time) (Exit, error) {
	if entry.Slot < supplementalSlotBase || entry.Slot > supplementalSlotMax {
		return Exit{}, errors.New("slot is outside the reserved supplemental range")
	}
	entry.SourceName = strings.TrimSpace(entry.SourceName)
	if entry.SourceName == "" || len(entry.SourceName) > 80 || strings.ContainsAny(entry.SourceName, "\r\n\x00") {
		return Exit{}, errors.New("invalid source name")
	}
	proxyIP, err := publicIPv4(entry.Host)
	if err != nil {
		return Exit{}, fmt.Errorf("invalid proxy address: %w", err)
	}
	exitIP, err := publicIPv4(entry.ExitIP)
	if err != nil {
		return Exit{}, fmt.Errorf("invalid measured exit address: %w", err)
	}
	if entry.Port < 1 || entry.Port > 65535 || entry.LatencyMS < 0 || entry.LatencyMS > 120000 {
		return Exit{}, errors.New("invalid proxy port or latency")
	}
	if (entry.Username == "") != (entry.Password == "") || len(entry.Username) > 256 || len(entry.Password) > 256 {
		return Exit{}, errors.New("SOCKS credentials must be both empty or both present")
	}
	entry.Country = strings.ToUpper(strings.TrimSpace(entry.Country))
	if len(entry.Country) != 2 || entry.Country[0] < 'A' || entry.Country[0] > 'Z' || entry.Country[1] < 'A' || entry.Country[1] > 'Z' {
		return Exit{}, errors.New("country must be an ISO alpha-2 code")
	}
	if entry.CheckedAt.IsZero() || entry.ExpiresAt.IsZero() || entry.CheckedAt.After(now.Add(5*time.Minute)) ||
		entry.CheckedAt.Before(manifest.GeneratedAt.Add(-5*time.Minute)) || !entry.ExpiresAt.After(now) ||
		entry.ExpiresAt.After(manifest.ExpiresAt) || !entry.ExpiresAt.After(entry.CheckedAt) {
		return Exit{}, errors.New("probe evidence is stale or inconsistent")
	}
	switch entry.SourceCategory {
	case exitSourceHome:
		if entry.Native || (entry.IPType != "strict_residential" && entry.IPType != "likely_residential") {
			return Exit{}, errors.New("new residential exit lacks residential evidence")
		}
	case exitSourceNativeDC:
		if !entry.Native || (entry.IPType != "datacenter" && entry.IPType != "business_isp") {
			return Exit{}, errors.New("new native datacenter exit lacks native datacenter evidence")
		}
	default:
		return Exit{}, errors.New("source category is not allowed in the supplemental pool")
	}
	country, city := entry.Country, strings.TrimSpace(entry.City)
	residential := entry.SourceCategory == exitSourceHome
	hosting := entry.SourceCategory == exitSourceNativeDC
	profile := &EgressProfile{
		IP: exitIP, Protocol: "socks5", Country: &country, City: &city,
		IPType: entry.IPType, Residential: &residential, Hosting: &hosting,
		Confidence: "verified", Provider: entry.SourceName,
		QueriedAt:          entry.CheckedAt.UTC().Format(time.RFC3339Nano),
		ExpiresAt:          entry.ExpiresAt.UTC().Format(time.RFC3339Nano),
		IntelligenceStatus: "passed",
	}
	return Exit{
		Slot: entry.Slot, Host: proxyIP, Region: country, Country: country,
		ExitIP: exitIP, Status: "up", Since: entry.CheckedAt.UTC(), Egress: profile,
		LatencyMS: entry.LatencyMS, SourceCategory: entry.SourceCategory,
		SourceName: entry.SourceName, Native: entry.Native,
		ProxyAddress: proxyIP, ProxyPort: entry.Port,
		SocksUser: entry.Username, SocksPass: entry.Password,
	}, nil
}

func publicIPv4(value string) (string, error) {
	trimmed := strings.TrimSpace(value)
	ip := net.ParseIP(trimmed)
	if ip == nil || ip.To4() == nil || strings.Contains(trimmed, ":") {
		return "", errors.New("a literal IPv4 address is required")
	}
	ip = ip.To4()
	if ip.IsPrivate() || ip.IsLoopback() || ip.IsUnspecified() || ip.IsMulticast() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return "", errors.New("address is not public")
	}
	// Reject documentation, benchmarking, carrier-grade NAT and reserved ranges
	// that net.IP does not uniformly classify as private on supported Go builds.
	if ip[0] == 0 || ip[0] == 127 || ip[0] >= 224 ||
		(ip[0] == 100 && ip[1]&0xc0 == 64) ||
		(ip[0] == 169 && ip[1] == 254) ||
		(ip[0] == 192 && (ip[1] == 0 || (ip[1] == 2))) ||
		(ip[0] == 198 && (ip[1] == 18 || ip[1] == 19 || ip[1] == 51)) ||
		(ip[0] == 203 && ip[1] == 0) {
		return "", errors.New("address is reserved")
	}
	return ip.String(), nil
}
