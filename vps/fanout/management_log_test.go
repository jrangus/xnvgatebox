package main

import (
	"os"
	"strings"
	"testing"
)

func TestManagementLogDoesNotMixPlaceholderAndListenAddress(t *testing.T) {
	source, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatalf("read main.go: %v", err)
	}
	if strings.Contains(string(source), "<本机IP>%s") {
		t.Fatal("management URL log combines a host placeholder with the real listen address")
	}
}
