package main

// The manager supplies an independently measured OpenVPN baseline to the
// shared Python adapter. No classifier or intelligence HTTP client lives here.
import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

type EgressProfile struct {
	IP                 string           `json:"ip"`
	Protocol           string           `json:"protocol"`
	CountryEvidence    *CountryEvidence `json:"country_evidence,omitempty"`
	CountryStatus      string           `json:"country_status,omitempty"`
	Country            *string          `json:"country"`
	City               *string          `json:"city,omitempty"`
	ASN                *string          `json:"asn"`
	ISP                *string          `json:"isp"`
	IPType             string           `json:"ip_type"`
	Hosting            *bool            `json:"hosting"`
	Mobile             *bool            `json:"mobile"`
	Residential        *bool            `json:"residential"`
	Proxy              *bool            `json:"proxy"`
	VPN                *bool            `json:"vpn"`
	Abuse              *bool            `json:"abuse"`
	Reason             string           `json:"reason"`
	Confidence         string           `json:"confidence"`
	Provider           string           `json:"provider,omitempty"`
	QueriedAt          string           `json:"queried_at,omitempty"`
	ExpiresAt          string           `json:"expires_at,omitempty"`
	RuleVersion        string           `json:"rule_version,omitempty"`
	IdentityAssurance  string           `json:"identity_assurance,omitempty"`
	CacheUsed          bool             `json:"cache_used"`
	IntelligenceStatus string           `json:"intelligence_status"`
	IntelligenceError  string           `json:"intelligence_error,omitempty"`
	Raw                json.RawMessage  `json:"raw,omitempty"`
}

func unknownOpenVPNEgress(ip, reason string) EgressProfile {
	return EgressProfile{IP: ip, Protocol: "openvpn", IPType: "unknown",
		Reason: reason, Confidence: "unknown", IntelligenceStatus: "failed", IntelligenceError: reason}
}

func envOr(name, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(name)); value != "" {
		return value
	}
	return fallback
}

func lookupOpenVPNEgress(workDir, ip string) EgressProfile {
	return lookupOpenVPNEgressWith(workDir, ip, cmdOutput)
}

func lookupOpenVPNEgressWith(workDir, ip string, run func(*exec.Cmd) ([]byte, error)) EgressProfile {
	return lookupOpenVPNEgressContextWith(context.Background(), workDir, ip, run)
}

func lookupOpenVPNEgressContext(parent context.Context, workDir, ip string) EgressProfile {
	return lookupOpenVPNEgressContextWith(parent, workDir, ip, cmdOutput)
}

func lookupOpenVPNEgressContextWith(parent context.Context, workDir, ip string, run func(*exec.Cmd) ([]byte, error)) EgressProfile {
	ctx, cancel := context.WithTimeout(parent, 40*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "python3",
		envOr("FANOUT_TOOLBOX_SCRIPT", "/usr/local/lib/xnvgatebox/scripts/toolbox.py"),
		"--config", envOr("FANOUT_POOL_CONFIG", "/etc/xnvgatebox/pool.json"),
		"--env-file", envOr("FANOUT_INTELLIGENCE_ENV_FILE", "/etc/xnvgatebox/intelligence.env"),
		"profile-openvpn", "--ip", ip, "--country", "--cache", filepath.Join(workDir, "intelligence", "cache.json"))
	out, err := run(cmd)
	if err != nil {
		// Never expose subprocess output, URLs or token-bearing provider errors.
		return unknownOpenVPNEgress(ip, "intelligence_process_failed")
	}
	return decodeOpenVPNEgress(out, ip)
}

func decodeOpenVPNEgress(blob []byte, ip string) EgressProfile {
	return decodeMeasuredEgress(blob, ip, "openvpn")
}

func decodeMeasuredEgress(blob []byte, ip, protocol string) EgressProfile {
	unknown := func(reason string) EgressProfile {
		p := unknownOpenVPNEgress(ip, reason)
		p.Protocol = protocol
		return p
	}
	var image EgressProfile
	if err := json.Unmarshal(blob, &image); err != nil || image.IP != ip || image.Protocol != protocol {
		return unknown("intelligence_response_mismatch")
	}
	switch image.IPType {
	case "strict_residential", "likely_residential", "mobile", "datacenter", "business_isp", "unknown":
	default:
		return unknown("intelligence_invalid_type")
	}
	if image.IntelligenceStatus == "passed" {
		expiry, err := time.Parse(time.RFC3339Nano, image.ExpiresAt)
		if err != nil || !expiry.After(time.Now()) || image.Provider == "" || image.QueriedAt == "" || image.RuleVersion == "" {
			return unknown("intelligence_stale_or_incomplete")
		}
	} else if image.IPType != "unknown" || (image.IntelligenceStatus != "failed" && image.IntelligenceStatus != "not_configured") {
		return unknown("intelligence_unverified_type")
	}
	if verifiedProfileCountry(image) == "" {
		image.Country = nil
	}
	return image
}

// Runtime evidence is not restored as healthy after a restart or replacement.
// API snapshots omit the raw provider response; it remains in private evidence.
func (t *Tunnel) clearEgress() {
	t.mu.Lock()
	t.egress = nil
	t.egressExpectedIP, t.egressActualIP, t.egressVerifiedAt = "", "", ""
	t.egressNodeHost, t.egressProfileDigest = "", ""
	t.LatencyMS = 0
	t.mu.Unlock()
}

func (t *Tunnel) acceptExitEvidence(expected, actual string, image EgressProfile) error {
	if expected == "" || expected != actual || image.IP != expected || image.Protocol != t.transport() {
		return fmt.Errorf("%s 基线、画像与 SOCKS 出口不一致", strings.ToUpper(t.transport()))
	}
	t.mu.Lock()
	t.egress = &image
	t.egressExpectedIP, t.egressActualIP = expected, actual
	t.egressVerifiedAt = time.Now().UTC().Format(time.RFC3339Nano)
	t.egressNodeHost, t.egressProfileDigest = t.Node.HostName, profileDigest(t.Node.Config)
	t.mu.Unlock()
	return nil
}

func (t *Tunnel) egressSnapshot(private bool) *EgressProfile {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.egressSnapshotLocked(private)
}

func (t *Tunnel) egressSnapshotLocked(private bool) *EgressProfile {
	if t.egress == nil || t.Status != "up" {
		return nil
	}
	image := *t.egress
	if image.IP != t.ExitIP || t.egressNodeHost != t.Node.HostName || t.egressProfileDigest != profileDigest(t.Node.Config) {
		return nil
	}
	if image.IntelligenceStatus == "passed" {
		expiry, err := time.Parse(time.RFC3339Nano, image.ExpiresAt)
		if err != nil || !expiry.After(time.Now()) {
			image.IPType, image.IntelligenceStatus = "unknown", "stale"
			image.Reason, image.IntelligenceError, image.Confidence = "intelligence_stale", "intelligence_stale", "unknown"
			image.Residential = nil
		}
	}
	image.CountryStatus = "unknown"
	if verifiedProfileCountry(image) != "" {
		image.CountryStatus = "passed"
	} else {
		image.Country = nil
		if image.CountryEvidence != nil {
			image.CountryStatus = image.CountryEvidence.Status
			if image.CountryStatus == "passed" {
				image.CountryStatus = "stale"
			}
		}
	}
	if !private {
		image.Raw = nil
	}
	return &image
}

type slotHealthEvidence struct {
	SlotID         string         `json:"slot_id"`
	Hostname       string         `json:"hostname"`
	PoolNodeID     string         `json:"pool_node_id,omitempty"`
	ProfileSHA256  string         `json:"profile_sha256"`
	SocksPort      int            `json:"socks_port"`
	Status         string         `json:"status"`
	ExpectedExitIP string         `json:"expected_exit_ip,omitempty"`
	ActualExitIP   string         `json:"actual_exit_ip,omitempty"`
	VerifiedAt     string         `json:"verified_at,omitempty"`
	Egress         *EgressProfile `json:"egress"`
	LatencyMS      float64        `json:"latency_ms,omitempty"`
	Policy         *SlotPolicy    `json:"policy,omitempty"`
	Transport      string         `json:"transport,omitempty"`
	SourceCategory string         `json:"source_category,omitempty"`
}

func (m *Manager) saveSlotHealth() error {
	entries := make([]slotHealthEvidence, 0)
	for _, t := range m.Tunnels() {
		t.mu.Lock()
		image := t.egressSnapshotLocked(true)
		entry := slotHealthEvidence{SlotID: fmt.Sprintf("slot-%02d", t.Slot),
			Hostname: t.Node.HostName, PoolNodeID: t.Node.PoolNodeID,
			ProfileSHA256: profileDigest(t.Node.Config), SocksPort: t.Port, Status: t.Status, Egress: image, LatencyMS: t.LatencyMS, Policy: t.Policy,
			Transport: t.transport(), SourceCategory: t.sourceCategory()}
		// An IP left from a failed probe is not a successful SOCKS observation.
		if t.Status == "up" && image != nil {
			entry.ExpectedExitIP = t.egressExpectedIP
			entry.ActualExitIP = t.egressActualIP
			entry.VerifiedAt = t.egressVerifiedAt
		}
		t.mu.Unlock()
		entries = append(entries, entry)
	}
	blob, err := json.MarshalIndent(map[string]interface{}{
		"observed_by": "vps-managed-socks", "generated_at": time.Now().UTC().Format(time.RFC3339Nano), "slots": entries,
	}, "", "  ")
	if err != nil {
		return err
	}
	path := filepath.Join(m.workDir, "slot_health.json")
	f, err := os.CreateTemp(m.workDir, ".slot-health-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if _, err := f.Write(blob); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(f.Name(), path)
}

func profileDigest(config string) string {
	hash := sha256.Sum256([]byte(config))
	return hex.EncodeToString(hash[:])
}
