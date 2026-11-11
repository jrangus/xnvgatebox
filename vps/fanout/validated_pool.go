package main

// The VPS manager consumes the same Pool Builder output as Mode A.  It does
// not run a second VPN Gate scraper or infer residential status from a
// hostname.  OpenVPN is still re-tested locally because a serverless SSTP
// result is not evidence that this VPS can establish the same protocol.

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

type validatedPoolFile struct {
	Source poolSourceMetadata  `json:"source"`
	Nodes  []validatedPoolNode `json:"nodes"`
}

type validatedPoolNode struct {
	NodeID            string  `json:"node_id"`
	Hostname          string  `json:"hostname"`
	ServerIP          string  `json:"server_ip"`
	AdvertisedCountry string  `json:"advertised_country"`
	SourceScore       float64 `json:"source_score"`
	SourcePingMS      int     `json:"source_ping_ms"`
	Protocols         struct {
		OpenVPN struct {
			Status         string        `json:"status"`
			ProfileRef     string        `json:"profile_ref"`
			ExpectedExitIP string        `json:"expected_exit_ip"`
			Egress         EgressProfile `json:"egress"`
		} `json:"openvpn"`
		SSTP struct {
			Candidates     []SstpEndpoint `json:"candidates"`
			Status         string         `json:"status"`
			ExpectedExitIP string         `json:"expected_exit_ip"`
			Egress         struct {
				IPType string `json:"ip_type"`
				ISP    string `json:"isp"`
				ASN    string `json:"asn"`
			} `json:"egress"`
		} `json:"sstp"`
	} `json:"protocols"`
	ModeA struct {
		Status     string `json:"status"`
		VerifiedAt string `json:"verified_at"`
	} `json:"mode_a"`
}

func fetchNodesFromValidatedPool(poolPath string) ([]Node, error) {
	blob, err := os.ReadFile(poolPath)
	if err != nil {
		return nil, fmt.Errorf("读取 validated node pool 失败: %w", err)
	}
	var pool validatedPoolFile
	if err := json.Unmarshal(blob, &pool); err != nil {
		return nil, fmt.Errorf("解析 validated node pool 失败: %w", err)
	}
	base := filepath.Dir(poolPath)
	poolSource := publicPoolSource(pool.Source)
	var nodes []Node
	for _, item := range pool.Nodes {
		if strings.TrimSpace(item.Hostname) == "" || strings.TrimSpace(item.Protocols.OpenVPN.ProfileRef) == "" {
			continue
		}
		profile := filepath.Clean(filepath.Join(base, item.Protocols.OpenVPN.ProfileRef))
		if !withinDir(base, profile) {
			return nil, fmt.Errorf("OpenVPN profile escapes pool directory: %s", item.Protocols.OpenVPN.ProfileRef)
		}
		config, err := os.ReadFile(profile)
		if err != nil {
			continue
		}
		hash := sha256.Sum256(config)
		// A changed or unbound profile is not silently accepted.  The pool
		// builder stores the same digest next to the profile reference.
		want := strings.TrimSuffix(filepath.Base(profile), filepath.Ext(profile))
		if len(want) == 64 {
			got := hex.EncodeToString(hash[:])
			if !strings.EqualFold(got, want) {
				continue
			}
		}
		// SSTP evidence belongs to SSTP, even if its IP happens to match.
		// Only fresh, IP-bound OpenVPN evidence can describe this candidate.
		image := item.Protocols.OpenVPN.Egress
		expiry, expiryErr := time.Parse(time.RFC3339Nano, image.ExpiresAt)
		ipType, isp, asn, expected := "unknown", "", "", ""
		if item.Protocols.OpenVPN.Status == "passed" && image.Protocol == "openvpn" &&
			image.IntelligenceStatus == "passed" && image.Provider != "" && image.QueriedAt != "" && image.RuleVersion != "" && image.IP != "" &&
			image.IP == item.Protocols.OpenVPN.ExpectedExitIP && expiryErr == nil && expiry.After(time.Now()) {
			ipType = image.IPType
			if image.ISP != nil {
				isp = *image.ISP
			}
			if image.ASN != nil {
				asn = *image.ASN
			}
			expected = image.IP
		}
		residential := ipType == "strict_residential" || ipType == "likely_residential"
		var publicImage *EgressProfile
		if expected != "" {
			image.Raw = nil
			publicImage = &image
		}
		nodes = append(nodes, Node{
			HostName:            item.Hostname,
			IP:                  item.ServerIP,
			Country:             item.AdvertisedCountry,
			CountryCode:         item.AdvertisedCountry,
			Ping:                item.SourcePingMS,
			SpeedMbps:           item.SourceScore,
			Residential:         residential,
			Config:              string(config),
			PoolNodeID:          item.NodeID,
			IPType:              ipType,
			ISP:                 isp,
			ASN:                 asn,
			ExpectedExitIP:      expected,
			OpenVPNEgress:       publicImage,
			SSTPStatus:          item.Protocols.SSTP.Status,
			SSTPCandidates:      append([]SstpEndpoint(nil), item.Protocols.SSTP.Candidates...),
			OpenVPNStatus:       item.Protocols.OpenVPN.Status,
			FullChainVerified:   item.ModeA.Status == "passed",
			LastVerified:        item.ModeA.VerifiedAt,
			CandidateSourceKind: poolSource.Kind,
			CandidateSource:     poolSource.Label,
		})
	}
	if len(nodes) == 0 {
		return nil, fmt.Errorf("validated node pool 没有可用 OpenVPN profile")
	}
	sort.Slice(nodes, func(i, j int) bool {
		if nodes[i].CountryCode != nodes[j].CountryCode {
			return nodes[i].CountryCode < nodes[j].CountryCode
		}
		// This is only a reachability preference for the first VPS probe.  It
		// does not label a node residential; that still requires the shared
		// intelligence classifier.  VPN Gate's own public-vpn machines are
		// frequently full, so try volunteer candidates before them.
		pi := strings.HasPrefix(strings.ToLower(nodes[i].HostName), "public-vpn-")
		pj := strings.HasPrefix(strings.ToLower(nodes[j].HostName), "public-vpn-")
		if pi != pj {
			return !pi
		}
		return nodes[i].SpeedMbps > nodes[j].SpeedMbps
	})
	return nodes, nil
}

func withinDir(base, path string) bool {
	baseAbs, err1 := filepath.Abs(base)
	pathAbs, err2 := filepath.Abs(path)
	if err1 != nil || err2 != nil {
		return false
	}
	rel, err := filepath.Rel(baseAbs, pathAbs)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(os.PathSeparator))
}
