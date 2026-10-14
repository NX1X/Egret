//go:build linux

package enforcer

import (
	"strings"
	"testing"
)

func TestRunIDIsRandom(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 100; i++ {
		id, err := newRunID()
		if err != nil {
			t.Fatal(err)
		}
		if len(id) != 16 || strings.Trim(id, "0123456789abcdef") != "" {
			t.Fatalf("newRunID() = %q, want 16 hex characters", id)
		}
		seen[id] = true
	}
	// Not derived from the pid: every draw differs.
	if len(seen) != 100 {
		t.Errorf("only %d distinct run ids in 100 draws", len(seen))
	}
	if got := tableName("ab12"); got != "egret_ab12" {
		t.Errorf("tableName = %q, want egret_ab12", got)
	}
}

func TestDNSRules(t *testing.T) {
	rules, err := dnsRules("127.53.7.9:53")
	if err != nil {
		t.Fatalf("dnsRules: %v", err)
	}
	if len(rules) != 5 {
		t.Fatalf("got %d rules, want 5: %q", len(rules), rules)
	}
	// Order is the security property: accept the proxy, drop all other DNS on
	// loopback, and only then accept the rest of loopback.
	if !strings.HasPrefix(rules[0], "ip daddr 127.53.7.9 ") || !strings.HasSuffix(rules[0], "th dport 53 accept") {
		t.Errorf("rule 0 = %q, want accept DNS to the proxy", rules[0])
	}
	if !strings.HasPrefix(rules[1], `oifname "lo" `) || !strings.HasSuffix(rules[1], "th dport 53 counter drop") {
		t.Errorf("rule 1 = %q, want drop other loopback DNS", rules[1])
	}
	// Docker's embedded DNS: the nat rule rewrites port 53 before this filter.
	if !strings.Contains(rules[2], "ct original proto-dst 53") || !strings.HasSuffix(rules[2], "drop") {
		t.Errorf("rule 2 = %q, want drop of NAT-rewritten DNS", rules[2])
	}
	if rules[3] != `oifname "lo" ip daddr 127.0.0.11 counter drop` {
		t.Errorf("rule 3 = %q, want drop of Docker's embedded DNS address", rules[3])
	}
	if rules[4] != `oifname "lo" accept` {
		t.Errorf("rule 4 = %q, want loopback accept last", rules[4])
	}
	for _, r := range rules[:3] {
		if !strings.Contains(r, "meta l4proto { tcp, udp }") {
			t.Errorf("rule %q must cover both TCP and UDP", r)
		}
	}

	for _, bad := range []string{"", "127.53.7.9", "10.0.0.1:53", "127.53.7.9:5353", "[::1]:53", "nope:53"} {
		if _, err := dnsRules(bad); err == nil {
			t.Errorf("dnsRules(%q) = nil error, want refusal", bad)
		}
	}
}
