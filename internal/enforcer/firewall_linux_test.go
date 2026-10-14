//go:build linux

package enforcer

import (
	"strings"
	"testing"
)

func TestTableNameIsPerRun(t *testing.T) {
	if tableName(42) == tableName(43) {
		t.Fatal("two runs share an nft table name")
	}
	if got := tableName(42); got != "egret_42" {
		t.Errorf("tableName(42) = %q, want egret_42", got)
	}
}

func TestDNSRules(t *testing.T) {
	rules, err := dnsRules("127.53.7.9:53")
	if err != nil {
		t.Fatalf("dnsRules: %v", err)
	}
	if len(rules) != 3 {
		t.Fatalf("got %d rules, want 3: %q", len(rules), rules)
	}
	// Order is the security property: accept the proxy, drop all other DNS on
	// loopback, and only then accept the rest of loopback.
	if !strings.HasPrefix(rules[0], "ip daddr 127.53.7.9 ") || !strings.HasSuffix(rules[0], "th dport 53 accept") {
		t.Errorf("rule 0 = %q, want accept DNS to the proxy", rules[0])
	}
	if !strings.HasPrefix(rules[1], `oifname "lo" `) || !strings.HasSuffix(rules[1], "th dport 53 counter drop") {
		t.Errorf("rule 1 = %q, want drop other loopback DNS", rules[1])
	}
	if rules[2] != `oifname "lo" accept` {
		t.Errorf("rule 2 = %q, want loopback accept", rules[2])
	}
	for _, r := range rules[:2] {
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
