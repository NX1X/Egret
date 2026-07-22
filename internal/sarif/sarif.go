// Package sarif converts an Egret run (event.Session) into SARIF 2.1.0, the
// format GitHub Code Scanning ingests. Violations become SARIF results so they
// surface as native security alerts on the Security tab and inline on PRs.
//
// Runtime violations are not tied to a source line, so results are located on the
// policy file when its path is known, else on a suggested default policy path.
// Every result ALWAYS carries a location: GitHub Code Scanning rejects a result
// with an empty locations array ("expected at least one location").
//
// Uses only the standard library (encoding/json via struct tags), per the
// project dependency policy.
package sarif

import (
	"strings"

	"github.com/NX1X/Egret/internal/event"
)

const (
	version     = "2.1.0"
	schemaURI   = "https://json.schemastore.org/sarif-2.1.0.json"
	toolName    = "Egret"
	toolInfoURI = "https://github.com/NX1X/Egret"
	// Runtime findings have no source line; when no policy file path is known we
	// still MUST emit a location (Code Scanning rejects a result without one), so
	// we attribute to the conventional policy file a user would create to fix it.
	defaultPolicyURI = ".github/egret-policy.yaml"
)

// Log is the root SARIF document.
type Log struct {
	Schema  string `json:"$schema"`
	Version string `json:"version"`
	Runs    []Run  `json:"runs"`
}

type Run struct {
	Tool    Tool     `json:"tool"`
	Results []Result `json:"results"`
}

type Tool struct {
	Driver Driver `json:"driver"`
}

type Driver struct {
	Name           string `json:"name"`
	InformationURI string `json:"informationUri"`
	Version        string `json:"version,omitempty"`
	Rules          []Rule `json:"rules"`
}

type Rule struct {
	ID                   string `json:"id"`
	Name                 string `json:"name"`
	ShortDescription     Text   `json:"shortDescription"`
	DefaultConfiguration Config `json:"defaultConfiguration"`
}

type Config struct {
	Level string `json:"level"`
}

type Result struct {
	RuleID    string     `json:"ruleId"`
	Level     string     `json:"level"`
	Message   Text       `json:"message"`
	Locations []Location `json:"locations,omitempty"`
}

type Location struct {
	PhysicalLocation Physical `json:"physicalLocation"`
}

type Physical struct {
	ArtifactLocation Artifact `json:"artifactLocation"`
	Region           *Region  `json:"region,omitempty"`
}

type Artifact struct {
	URI string `json:"uri"`
}

type Region struct {
	StartLine int `json:"startLine"`
}

type Text struct {
	Text string `json:"text"`
}

// FromSession builds a SARIF log from a session's violations. policyPath, when
// non-empty, is used as the result location (the file a user edits to fix the
// finding). toolVersion is optional (the egret build version).
func FromSession(s *event.Session, policyPath, toolVersion string) Log {
	var rules []Rule
	seen := map[string]bool{}
	var results []Result

	for _, v := range s.Violations {
		id := ruleID(v)
		if !seen[id] {
			seen[id] = true
			rules = append(rules, Rule{
				ID:                   id,
				Name:                 ruleName(v),
				ShortDescription:     Text{Text: v.Reason},
				DefaultConfiguration: Config{Level: level(v)},
			})
		}
		results = append(results, Result{
			RuleID:    id,
			Level:     level(v),
			Message:   Text{Text: message(v)},
			Locations: locations(policyPath),
		})
	}

	return Log{
		Schema:  schemaURI,
		Version: version,
		Runs: []Run{{
			Tool: Tool{Driver: Driver{
				Name:           toolName,
				InformationURI: toolInfoURI,
				Version:        toolVersion,
				Rules:          rules,
			}},
			Results: results,
		}},
	}
}

// ruleID is a stable, kebab-cased identifier like "egress/domain-not-in-allowlist".
func ruleID(v event.Violation) string {
	return string(v.Kind) + "/" + slug(v.Reason)
}

func ruleName(v event.Violation) string {
	return string(v.Kind) + "-" + slug(v.Reason)
}

// level maps an Egret violation to a SARIF level. A blocked (enforced) violation
// is an error; an audit-mode/flagged one is a warning.
func level(v event.Violation) string {
	if v.Blocked {
		return "error"
	}
	return "warning"
}

func message(v event.Violation) string {
	if v.Detail == "" {
		return v.Reason
	}
	return v.Reason + ": " + v.Detail
}

func locations(policyPath string) []Location {
	uri := policyPath
	if uri == "" {
		uri = defaultPolicyURI
	}
	return []Location{{PhysicalLocation: Physical{
		ArtifactLocation: Artifact{URI: uri},
		Region:           &Region{StartLine: 1},
	}}}
}

// slug lowercases and replaces runs of non-alphanumeric characters with a single
// hyphen, trimming leading/trailing hyphens.
func slug(s string) string {
	var b strings.Builder
	prevDash := false
	for _, r := range strings.ToLower(s) {
		switch {
		case (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9'):
			b.WriteRune(r)
			prevDash = false
		default:
			if !prevDash {
				b.WriteByte('-')
				prevDash = true
			}
		}
	}
	return strings.Trim(b.String(), "-")
}
