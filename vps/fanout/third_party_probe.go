package main

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// HTTP's SOCKS5 dialer performs remote DNS and RFC1929 authentication. No
// supplier passwords enter a command line, process environment or raw error.
func probeThirdParty(ctx context.Context, p ThirdPartyProxy, dir string) ThirdPartyRecord {
	client := thirdPartyHTTPClient(p)
	defer client.CloseIdleConnections()
	r := probeThirdPartyRequests(ctx, p, client, exitIPEchoURLs, "https://example.com/")
	if r.Status != "passed" {
		return r
	}
	image := lookupThirdPartyEgress(ctx, dir, r.ActualIP)
	r.Country = verifiedProfileCountry(image)
	if image.CountryEvidence != nil && r.Country != "" {
		if exp, err := time.Parse(time.RFC3339Nano, image.CountryEvidence.ExpiresAt); err == nil && exp.Before(r.ExpiresAt) {
			r.ExpiresAt = exp
		}
	}
	r.IPType = "unknown"
	r.Native = false
	r.CheckedAt = time.Now()
	return r
}

func thirdPartyHTTPClient(p ThirdPartyProxy) *http.Client {
	u := &url.URL{Scheme: "socks5h", Host: net.JoinHostPort(p.Host, strconv.Itoa(p.Port))}
	if p.Username != "" || p.Password != "" {
		u.User = url.UserPassword(p.Username, p.Password)
	}
	tr := &http.Transport{Proxy: http.ProxyURL(u), TLSHandshakeTimeout: 15 * time.Second, DisableKeepAlives: true}
	return &http.Client{Transport: tr, Timeout: 20 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

func probeThirdPartyRequests(ctx context.Context, p ThirdPartyProxy, client *http.Client, echoURLs []string, contentURL string) ThirdPartyRecord {
	r := ThirdPartyRecord{Status: "failed", Code: "proxy_https_failed", Digest: thirdPartyDigest(p), IPType: "unknown", CheckedAt: time.Now(), ExpiresAt: time.Now().Add(time.Hour)}
	get := func(target string) ([]byte, bool) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
		if err != nil {
			return nil, false
		}
		start := time.Now()
		resp, err := client.Do(req)
		if err != nil {
			return nil, false
		}
		defer resp.Body.Close()
		b, err := io.ReadAll(io.LimitReader(resp.Body, 131073))
		lat := float64(time.Since(start).Microseconds()) / 1000
		if lat > r.LatencyMS {
			r.LatencyMS = lat
		}
		return b, err == nil && len(b) <= 131072 && resp.StatusCode == 200
	}
	for _, target := range echoURLs {
		b, ok := get(target)
		if !ok {
			return r
		}
		ip := strings.TrimSpace(string(b))
		if !sstpPublicIPv4(ip) {
			r.Code = "invalid_exit_ip"
			return r
		}
		if r.ActualIP != "" && r.ActualIP != ip {
			r.ActualIP = ""
			r.Code = "exit_changed"
			return r
		}
		r.ActualIP = ip
	}
	b, ok := get(contentURL)
	if !ok || !strings.Contains(string(b), "Example Domain") {
		r.Code = "proxy_content_failed"
		return r
	}
	r.Status, r.Code = "passed", ""
	r.CheckedAt = time.Now()
	return r
}

func lookupThirdPartyEgress(ctx context.Context, dir, ip string) EgressProfile {
	unknown := EgressProfile{IP: ip, Protocol: "socks5", IPType: "unknown"}
	bounded, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(bounded, "python3", envOr("FANOUT_TOOLBOX_SCRIPT", "/usr/local/lib/xnvgatebox/scripts/toolbox.py"), "--config", envOr("FANOUT_POOL_CONFIG", "/etc/xnvgatebox/pool.json"), "--env-file", envOr("FANOUT_INTELLIGENCE_ENV_FILE", "/etc/xnvgatebox/intelligence.env"), "profile-socks5", "--ip", ip, "--country", "--cache", filepath.Join(dir, "intelligence", "socks5-cache.json"))
	// The supplemental pool uses only the independent country lookup. Explicit
	// empty values prevent the private env file from enabling IP classification.
	cmd.Env = append(os.Environ(), "INTELLIGENCE_URL_TEMPLATE=", "INTELLIGENCE_TOKEN=")
	out, err := cmdOutput(cmd)
	if err != nil {
		return unknown
	}
	image := decodeMeasuredEgress(out, ip, "socks5")
	if !safeProxyText(stringValue(image.City), 100) {
		image.City = nil
	}
	return image
}
