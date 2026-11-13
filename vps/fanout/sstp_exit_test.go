package main

import (
	"encoding/json"
	"testing"
	"time"
)

func promotableSSTPFixture(kind, actualCountry, sourceCountry string) (Node, CheckResult) {
	now := time.Now().UTC()
	host := "promote.opengw.net"
	node := Node{HostName: host, IP: "8.8.4.4", CountryCode: sourceCountry, SSTPCandidates: []SstpEndpoint{{Host: host, Port: 443}}}
	image := EgressProfile{
		IP: "8.8.8.8", Protocol: tunnelTransportSSTP, Country: &actualCountry, IPType: kind,
		Provider: "test", QueriedAt: now.Format(time.RFC3339Nano), ExpiresAt: now.Add(time.Hour).Format(time.RFC3339Nano),
		RuleVersion: "test-v1", IntelligenceStatus: "passed",
	}
	result := CheckResult{
		Host: host, Status: "passed", ObservedBy: "vps", Protocol: tunnelTransportSSTP, Port: 443,
		ActualIP: image.IP, IPType: kind, CheckedAt: now, ExpiresAt: now.Add(time.Hour), ProfileSHA: sstpProfile(node), Egress: &image,
	}
	return node, result
}

func TestValidatedSSTPSourceUsesUnclassifiedSSTPPool(t *testing.T) {
	node, result := promotableSSTPFixture("likely_residential", "US", "JP")
	source, native, policy, err := validatedSSTPSource(node, result, time.Now().UTC())
	if err != nil || source != exitSourceSSTP || native || policy.Country != "" || len(policy.AllowedIPTypes) != 1 || policy.AllowedIPTypes[0] != "unknown" {
		t.Fatalf("SSTP promotion category wrong: %q %v %+v %v", source, native, policy, err)
	}
	result.Egress = nil
	result.IPType = "unknown"
	if _, _, _, err = validatedSSTPSource(node, result, time.Now().UTC()); err != nil {
		t.Fatalf("unclassified measured SSTP was not promotable: %v", err)
	}
	result.ExpiresAt = time.Now().Add(-time.Minute)
	if _, _, _, err = validatedSSTPSource(node, result, time.Now().UTC()); err == nil {
		t.Fatal("expired SSTP was promoted")
	}
}

func TestPersistentSSTPStateIsStrictAndBackwardCompatible(t *testing.T) {
	node, result := promotableSSTPFixture("strict_residential", "JP", "JP")
	state := persistedState{Tunnels: []persistedTunnel{{
		Slot: 2, Port: 17929, HostName: node.HostName, CountryCode: node.CountryCode, ServerIP: node.IP,
		SSTPCandidates: node.SSTPCandidates, Transport: tunnelTransportSSTP, SSTPPort: result.Port,
		SourceCategory: exitSourceLegacyHome, SocksUser: "user1234", SocksPass: "password1234",
		Policy: &SlotPolicy{Country: "JP", AllowedIPTypes: []string{"strict_residential"}},
	}}}
	blob, _ := json.Marshal(state)
	decoded, err := decodePersistedState(blob, maximumSlots, false)
	if err != nil {
		t.Fatal(err)
	}
	tunnels, err := prepareRestoredTunnels(decoded, nil)
	if err != nil || len(tunnels) != 1 || tunnels[0].transport() != tunnelTransportSSTP || tunnels[0].sourceCategory() != exitSourceSSTP || tunnels[0].SSTPPort != 443 || tunnels[0].Policy.AllowedIPTypes[0] != "unknown" {
		t.Fatalf("SSTP state restore wrong: %+v %v", tunnels, err)
	}
	// A current pool row with the same hostname but another address must not
	// replace the endpoint that was actually measured before persistence.
	current := node
	current.IP = "1.1.1.1"
	current.SSTPCandidates = []SstpEndpoint{{Host: node.HostName, Port: 8443}}
	tunnels, err = prepareRestoredTunnels(decoded, []Node{current})
	if err != nil || tunnels[0].Node.IP != node.IP || tunnels[0].SSTPPort != 443 || len(tunnels[0].Node.SSTPCandidates) != 1 || tunnels[0].Node.SSTPCandidates[0].Port != 443 {
		t.Fatalf("SSTP restore replaced the verified endpoint: %+v %v", tunnels, err)
	}
	state.Tunnels[0].ServerIP = "127.0.0.1"
	blob, _ = json.Marshal(state)
	if _, err := decodePersistedState(blob, maximumSlots, false); err == nil {
		t.Fatal("private SSTP server address accepted from state")
	}
	legacy := []byte(`{"tunnels":[{"slot":1,"port":17928,"hostname":"legacy.opengw.net","country_code":"JP","config":"client"}]}`)
	decoded, err = decodePersistedState(legacy, maximumSlots, false)
	if err != nil || decoded.Tunnels[0].Transport != tunnelTransportOpenVPN || decoded.Tunnels[0].SourceCategory != exitSourceStable {
		t.Fatalf("legacy OpenVPN state migration failed: %+v %v", decoded, err)
	}
}

func TestValidatedSSTPSourceRejectsExpiredObservation(t *testing.T) {
	node, result := promotableSSTPFixture("strict_residential", "JP", "JP")
	result.ExpiresAt = time.Now().UTC().Add(-time.Minute)
	if _, _, _, err := validatedSSTPSource(node, result, time.Now().UTC()); err == nil {
		t.Fatal("expired SSTP observation was promoted")
	}
}

func TestValidatedSSTPSourceDoesNotRequireIntelligence(t *testing.T) {
	node, result := promotableSSTPFixture("unknown", "JP", "JP")
	result.Egress = nil
	_, _, _, err := validatedSSTPSource(node, result, time.Now().UTC())
	if err != nil {
		t.Fatalf("missing intelligence blocked a measured SSTP exit: %v", err)
	}
}
