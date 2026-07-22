// Package audit turns an observed session into a suggested egress allowlist -
// the basis for `egret audit --emit policy.yaml`.
package audit

import (
	"fmt"
	"sort"
	"strings"

	"github.com/NX1X/Egret/internal/event"
	"github.com/NX1X/Egret/internal/policy"
)

// Suggestion is the aggregated result of an audit run.
type Suggestion struct {
	// Domains observed during the run, deduped and sorted.
	Domains []string
	// RawIPs are destinations reached with no DNS correlation (potential gaps
	// the user must decide about explicitly).
	RawIPs []string
}

// Analyze aggregates a session's connections into a Suggestion.
func Analyze(s *event.Session) Suggestion {
	domainSet := map[string]struct{}{}
	ipSet := map[string]struct{}{}
	for _, c := range s.Connections {
		if c.Domain != "" {
			domainSet[strings.ToLower(c.Domain)] = struct{}{}
		} else if c.Daddr != nil && !c.Daddr.IsLoopback() {
			ipSet[c.Daddr.String()] = struct{}{}
		}
	}
	return Suggestion{
		Domains: sortedKeys(domainSet),
		RawIPs:  sortedKeys(ipSet),
	}
}

// Policy builds a policy.Policy from the suggestion, ready to marshal. It keeps
// the input policy's non-egress settings and replaces the allowlist.
func (sug Suggestion) Policy(base *policy.Policy) *policy.Policy {
	out := *base
	out.Mode = policy.ModeBlock // a suggested allowlist is meant for enforcement
	out.Egress.AllowedEndpoints = append([]string(nil), sug.Domains...)
	return &out
}

// Markdown renders a human-readable summary of the suggestion.
func (sug Suggestion) Markdown() string {
	var b strings.Builder
	fmt.Fprintf(&b, "## Suggested allowlist\n\n")
	if len(sug.Domains) == 0 {
		fmt.Fprintf(&b, "_No domains observed._\n\n")
	} else {
		fmt.Fprintf(&b, "```yaml\negress:\n  allowed-endpoints:\n")
		for _, d := range sug.Domains {
			fmt.Fprintf(&b, "    - %s\n", d)
		}
		fmt.Fprintf(&b, "```\n\n")
	}
	if len(sug.RawIPs) > 0 {
		fmt.Fprintf(&b, "> ⚠️ %d raw-IP destination(s) had no DNS lookup and are "+
			"NOT in the suggested list - review manually:\n>\n", len(sug.RawIPs))
		for _, ip := range sug.RawIPs {
			fmt.Fprintf(&b, "> - `%s`\n", ip)
		}
		b.WriteString("\n")
	}
	return b.String()
}

func sortedKeys(m map[string]struct{}) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
