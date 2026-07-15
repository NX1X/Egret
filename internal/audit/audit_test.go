package audit

import (
	"net"
	"strings"
	"testing"

	"github.com/NX1X/Egret/internal/event"
	"github.com/NX1X/Egret/internal/policy"
)

func sampleSession() *event.Session {
	return &event.Session{
		Connections: []event.Connection{
			{Domain: "github.com", Daddr: net.IPv4(140, 82, 121, 4)},
			{Domain: "GitHub.com", Daddr: net.IPv4(140, 82, 121, 5)}, // dup after lowercasing
			{Domain: "api.github.com", Daddr: net.IPv4(140, 82, 121, 6)},
			{Daddr: net.IPv4(8, 8, 8, 8)},   // raw IP
			{Daddr: net.IPv4(127, 0, 0, 1)}, // loopback, ignored
		},
	}
}

func TestAnalyze(t *testing.T) {
	sug := Analyze(sampleSession())

	wantDomains := []string{"api.github.com", "github.com"}
	if strings.Join(sug.Domains, ",") != strings.Join(wantDomains, ",") {
		t.Errorf("Domains = %v, want %v (deduped, lowercased, sorted)", sug.Domains, wantDomains)
	}
	if len(sug.RawIPs) != 1 || sug.RawIPs[0] != "8.8.8.8" {
		t.Errorf("RawIPs = %v, want [8.8.8.8] (loopback excluded)", sug.RawIPs)
	}
}

func TestSuggestionPolicy(t *testing.T) {
	sug := Analyze(sampleSession())
	base := policy.Default()
	out := sug.Policy(base)

	if out.Mode != policy.ModeBlock {
		t.Errorf("suggested policy mode = %q, want block", out.Mode)
	}
	if len(out.Egress.AllowedEndpoints) != 2 {
		t.Errorf("allowed-endpoints = %v", out.Egress.AllowedEndpoints)
	}
	// Base must not be mutated.
	if base.Mode != policy.ModeAudit {
		t.Error("Policy() mutated the base policy")
	}
}

func TestSuggestionMarkdown(t *testing.T) {
	md := Analyze(sampleSession()).Markdown()
	if !strings.Contains(md, "github.com") {
		t.Errorf("markdown missing domain: %s", md)
	}
	if !strings.Contains(md, "8.8.8.8") {
		t.Errorf("markdown should warn about raw IPs: %s", md)
	}

	empty := Suggestion{}.Markdown()
	if !strings.Contains(empty, "No domains observed") {
		t.Errorf("empty suggestion markdown = %s", empty)
	}
}
