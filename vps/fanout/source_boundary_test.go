package main

import (
	"strings"
	"testing"
)

func TestSubscriptionSourceLabelsStayDistinct(t *testing.T) {
	for source, want := range map[string]string{
		exitSourceStable: "xnvgatebox稳定 / VPN Gate OpenVPN",
		exitSourceSSTP:   "SSTP 出口池",
	} {
		if got := subscriptionSourceLabel(source); got != want {
			t.Fatalf("source %q label = %q, want %q", source, got, want)
		}
	}
}

func TestIntegratedConsoleDoesNotOfferLoopbackSubscription(t *testing.T) {
	for _, required := range []string{
		`summary.backend !== "native"`,
		"xnvgatebox 本机订阅已停用",
		"请在 3x-ui 出口池中复制订阅组地址",
		`id="sourcePolicy"`,
		"OpenVPN 出口链路",
		"SSTP/PPP 检测",
	} {
		if !strings.Contains(indexHTML, required) {
			t.Fatalf("console source/subscription boundary missing %q", required)
		}
	}
	if strings.Contains(indexHTML, `id="sourceMirrorEnabled"`) {
		t.Fatal("ambiguous mirror checkbox remained in the console")
	}
}
