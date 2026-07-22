package sarif

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/NX1X/Egret/internal/event"
)

func sampleSession() *event.Session {
	return &event.Session{
		Mode: "block",
		Violations: []event.Violation{
			{Kind: event.KindConnection, Reason: "domain not in allowlist", Detail: "evil.com by node[22]", Blocked: true},
			{Kind: event.KindConnection, Reason: "domain not in allowlist", Detail: "tracker.io by node[23]", Blocked: true},
			{Kind: event.KindFile, Reason: "write to protected path", Detail: "/etc/passwd", Blocked: false},
		},
	}
}

func TestFromSessionStructure(t *testing.T) {
	log := FromSession(sampleSession(), "policy.yaml", "v0.1.0")

	if log.Version != "2.1.0" || log.Schema == "" {
		t.Fatalf("bad header: %+v", log)
	}
	if len(log.Runs) != 1 {
		t.Fatalf("want 1 run, got %d", len(log.Runs))
	}
	run := log.Runs[0]
	if run.Tool.Driver.Name != "Egret" || run.Tool.Driver.Version != "v0.1.0" {
		t.Errorf("driver = %+v", run.Tool.Driver)
	}

	// Three violations -> three results.
	if len(run.Results) != 3 {
		t.Fatalf("want 3 results, got %d", len(run.Results))
	}
	// Two share a reason -> rules deduped to two.
	if len(run.Tool.Driver.Rules) != 2 {
		t.Errorf("want 2 unique rules, got %d: %+v", len(run.Tool.Driver.Rules), run.Tool.Driver.Rules)
	}

	// Rule id is stable + kebab-cased.
	if run.Results[0].RuleID != "connection/domain-not-in-allowlist" {
		t.Errorf("ruleId = %q", run.Results[0].RuleID)
	}
	// Blocked -> error, flagged -> warning.
	if run.Results[0].Level != "error" {
		t.Errorf("blocked violation should be error, got %q", run.Results[0].Level)
	}
	if run.Results[2].Level != "warning" {
		t.Errorf("flagged violation should be warning, got %q", run.Results[2].Level)
	}
	// Message combines reason + detail.
	if !strings.Contains(run.Results[0].Message.Text, "evil.com") {
		t.Errorf("message = %q", run.Results[0].Message.Text)
	}
	// Location points at the policy file.
	if len(run.Results[0].Locations) != 1 ||
		run.Results[0].Locations[0].PhysicalLocation.ArtifactLocation.URI != "policy.yaml" {
		t.Errorf("location = %+v", run.Results[0].Locations)
	}
}

func TestFromSessionNoPolicyPath(t *testing.T) {
	log := FromSession(sampleSession(), "", "")
	// Every result must carry a location (Code Scanning rejects an empty locations
	// array); with no policy path it falls back to the suggested default policy file.
	l := log.Runs[0].Results[0].Locations
	if len(l) != 1 || l[0].PhysicalLocation.ArtifactLocation.URI != defaultPolicyURI {
		t.Errorf("want fallback location %q, got %+v", defaultPolicyURI, l)
	}
	// Version omitted when empty.
	b, _ := json.Marshal(log.Runs[0].Tool.Driver)
	if strings.Contains(string(b), `"version"`) {
		t.Errorf("empty version should be omitted: %s", b)
	}
}

func TestFromSessionEmpty(t *testing.T) {
	log := FromSession(&event.Session{}, "", "")
	if len(log.Runs) != 1 {
		t.Fatal("should still emit one run")
	}
	if len(log.Runs[0].Results) != 0 {
		t.Errorf("no violations -> no results, got %d", len(log.Runs[0].Results))
	}
	// Must still marshal to valid JSON.
	if _, err := json.Marshal(log); err != nil {
		t.Fatalf("marshal: %v", err)
	}
}

func TestSlug(t *testing.T) {
	cases := map[string]string{
		"domain not in allowlist": "domain-not-in-allowlist",
		"raw-ip egress":           "raw-ip-egress",
		"  Weird   Reason!! ":     "weird-reason",
	}
	for in, want := range cases {
		if got := slug(in); got != want {
			t.Errorf("slug(%q) = %q, want %q", in, got, want)
		}
	}
}
