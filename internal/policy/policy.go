// Package policy parses policy.yaml and evaluates observed events against it.
// It is the single source of truth for "is this allowed?" - the CLI, the
// enforcer, and the policy-lint skill all route decisions through Evaluate.
package policy

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"

	"github.com/NX1X/Egret/internal/event"
	"go.yaml.in/yaml/v3"
)

// SupportedVersion is the only policy schema version this build understands.
const SupportedVersion = 1

// Mode is the enforcement posture.
type Mode string

const (
	// ModeAudit logs violations but never blocks. Safe default.
	ModeAudit Mode = "audit"
	// ModeBlock enforces default-deny egress.
	ModeBlock Mode = "block"
)

// Policy is the parsed policy.yaml.
type Policy struct {
	Version int    `yaml:"version"`
	Extends string `yaml:"extends,omitempty"` // base policy: local path or "org://owner/repo[/path]"
	Mode    Mode   `yaml:"mode"`
	Egress  Egress `yaml:"egress"`
	File    File   `yaml:"filesystem"`
	Process Proc   `yaml:"process"`
	Report  Report `yaml:"report"`
}

type Egress struct {
	AllowedEndpoints []string `yaml:"allowed-endpoints"`
	// AllowedIPs are raw IP / CIDR egress destinations allowed WITHOUT a domain
	// (a private registry reached by IP, a metadata-free internal host, etc.).
	// Each entry is a single IP ("10.0.0.5", "2001:db8::1") or a CIDR
	// ("10.0.0.0/8", "2001:db8::/32"), v4 or v6. Complements allowed-endpoints:
	// domains resolve into the allow set dynamically, these are static.
	AllowedIPs []string `yaml:"allowed-ips"`
	BlockRawIP bool     `yaml:"block-raw-ip"`

	allowedNets []*net.IPNet // parsed AllowedIPs (bare IPs become /32 or /128)
}

type File struct {
	ProtectedPaths []string `yaml:"protected-paths"`
}

type Proc struct {
	Disallowed []string `yaml:"disallowed"`
}

type Report struct {
	Format           []string `yaml:"format"`
	OutputDir        string   `yaml:"output-dir"`
	GitHubJobSummary bool     `yaml:"github-job-summary"`
}

// Default returns a policy with safe defaults applied (audit mode, sensible
// report settings). Loaded policies are layered on top of these.
func Default() *Policy {
	return &Policy{
		Version: SupportedVersion,
		Mode:    ModeAudit,
		Egress:  Egress{BlockRawIP: true},
		Report: Report{
			Format:           []string{"markdown", "json"},
			OutputDir:        "./hardened-report",
			GitHubJobSummary: true,
		},
	}
}

// Resolver fetches the raw YAML for a non-file `extends` ref (e.g. an
// "org://owner/repo" reference resolved via the GitHub API). It is supplied by
// the caller so the policy package stays free of any network/GitHub dependency.
type Resolver func(ref string) ([]byte, error)

const maxExtendsDepth = 8

// Load reads, resolves (`extends`), and validates a policy file. Only local-file
// extends are supported; use LoadWithResolver for remote refs.
func Load(path string) (*Policy, error) { return LoadWithResolver(path, nil) }

// LoadWithResolver is Load with support for non-file `extends` refs via resolve.
func LoadWithResolver(path string, resolve Resolver) (*Policy, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading policy %q: %w", path, err)
	}
	p, err := parsePolicy(raw, filepath.Dir(path), resolve, 0)
	if err != nil {
		return nil, fmt.Errorf("policy %q: %w", path, err)
	}
	if err := p.Validate(); err != nil {
		return nil, fmt.Errorf("invalid policy %q: %w", path, err)
	}
	return p, nil
}

// parsePolicy resolves `extends` (recursively) into a base policy, then overlays
// this policy: scalars override the base (so a child can set block-raw-ip:false),
// while list fields (allowed-endpoints, protected-paths, disallowed) are UNIONed
// with the base - the common "org base + repo additions" case.
func parsePolicy(raw []byte, baseDir string, resolve Resolver, depth int) (*Policy, error) {
	if depth > maxExtendsDepth {
		return nil, fmt.Errorf("`extends` nested too deeply (cycle?)")
	}
	var head struct {
		Extends string `yaml:"extends"`
	}
	// The head probe only reads `extends`; other keys are validated in the strict
	// decode below, so ignore unknown fields here.
	if err := yaml.Unmarshal(raw, &head); err != nil {
		return nil, fmt.Errorf("parsing: %w", err)
	}

	var base *Policy
	if head.Extends != "" {
		baseRaw, baseRefDir, err := resolveRef(head.Extends, baseDir, resolve)
		if err != nil {
			return nil, err
		}
		base, err = parsePolicy(baseRaw, baseRefDir, resolve, depth+1)
		if err != nil {
			return nil, fmt.Errorf("extends %q: %w", head.Extends, err)
		}
	} else {
		base = Default()
	}

	// Capture base lists, then overlay this policy onto the base struct.
	be, bp, bd := base.Egress.AllowedEndpoints, base.File.ProtectedPaths, base.Process.Disallowed
	bi := base.Egress.AllowedIPs
	// Strict decode: an unknown/misspelled key (e.g. `allow-endpoints` instead of
	// `allowed-endpoints`, or `blocked-raw-ip`) is a silent-misconfiguration hazard -
	// the intended allowlist entry or protection simply never takes effect and
	// Validate() can't catch a field that never got set. Fail fast instead.
	dec := yaml.NewDecoder(bytes.NewReader(raw))
	dec.KnownFields(true)
	// io.EOF = empty document (no overlay); keep the base as-is.
	if err := dec.Decode(base); err != nil && !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("parsing: %w", err)
	}
	base.Egress.AllowedEndpoints = unionDedup(be, base.Egress.AllowedEndpoints)
	base.Egress.AllowedIPs = unionDedup(bi, base.Egress.AllowedIPs)
	base.File.ProtectedPaths = unionDedup(bp, base.File.ProtectedPaths)
	base.Process.Disallowed = unionDedup(bd, base.Process.Disallowed)
	base.Extends = ""
	return base, nil
}

// resolveRef returns the raw bytes for an extends ref plus the directory used to
// resolve any nested relative extends within it.
//
// A local `extends` is confined to baseDir (the directory of the policy that
// declared it): both absolute paths and "../" traversal that escape baseDir are
// rejected. policy.yaml is frequently the artifact an untrusted PR edits, so an
// unconfined `extends: ../../../../etc/somefile` would let a crafted policy pull
// an arbitrary local file in as its base. Confinement keeps the base policy
// inside the repo checkout the policy itself lives in.
func resolveRef(ref, baseDir string, resolve Resolver) ([]byte, string, error) {
	if !strings.Contains(ref, "://") { // local file, possibly relative
		if filepath.IsAbs(ref) {
			return nil, "", fmt.Errorf("extends %q: absolute paths are not allowed; use a path relative to the policy file", ref)
		}
		p := filepath.Join(baseDir, ref)
		root, rerr := filepath.Abs(baseDir)
		abs, aerr := filepath.Abs(p)
		if rerr != nil || aerr != nil {
			return nil, "", fmt.Errorf("extends %q: resolving path: %w", ref, errors.Join(rerr, aerr))
		}
		if abs != root && !strings.HasPrefix(abs, root+string(os.PathSeparator)) {
			return nil, "", fmt.Errorf("extends %q: path escapes the policy directory (%s)", ref, baseDir)
		}
		b, err := os.ReadFile(p)
		return b, filepath.Dir(p), err
	}
	if resolve == nil {
		return nil, "", fmt.Errorf("cannot resolve remote extends %q (no resolver configured)", ref)
	}
	b, err := resolve(ref)
	return b, baseDir, err
}

// unionDedup concatenates lists preserving order, dropping duplicates and empties.
func unionDedup(lists ...[]string) []string {
	seen := map[string]struct{}{}
	var out []string
	for _, l := range lists {
		for _, s := range l {
			if s == "" {
				continue
			}
			if _, ok := seen[s]; !ok {
				seen[s] = struct{}{}
				out = append(out, s)
			}
		}
	}
	return out
}

// Validate checks the schema constraints. It is intentionally strict so a typo
// fails fast rather than silently disabling enforcement.
func (p *Policy) Validate() error {
	if p.Version != SupportedVersion {
		return fmt.Errorf("version must be %d, got %d", SupportedVersion, p.Version)
	}
	switch p.Mode {
	case ModeAudit, ModeBlock:
	default:
		return fmt.Errorf("mode must be %q or %q, got %q", ModeAudit, ModeBlock, p.Mode)
	}
	for _, e := range p.Egress.AllowedEndpoints {
		if err := validateEndpoint(e); err != nil {
			return fmt.Errorf("allowed-endpoints: %w", err)
		}
	}
	// Parse allowed-ips into CIDRs once, here, so evaluation is a cheap Contains.
	nets, err := parseAllowedIPs(p.Egress.AllowedIPs)
	if err != nil {
		return fmt.Errorf("allowed-ips: %w", err)
	}
	p.Egress.allowedNets = nets
	for _, f := range p.Report.Format {
		switch f {
		case "markdown", "json", "sarif":
		default:
			return fmt.Errorf("report.format: unsupported %q (want markdown|json|sarif)", f)
		}
	}
	return nil
}

// validateEndpoint rejects schemes, paths, ports, and bare wildcards. A valid
// entry is a domain or a "*."-prefixed wildcard.
func validateEndpoint(e string) error {
	if e == "" {
		return fmt.Errorf("empty endpoint")
	}
	if strings.ContainsAny(e, "/:") {
		return fmt.Errorf("%q must be a bare domain (no scheme, port, or path)", e)
	}
	if e == "*" || e == "*." {
		return fmt.Errorf("%q is too broad; use a specific domain or *.example.com", e)
	}
	if strings.HasPrefix(e, "*.") {
		if strings.ContainsAny(e[2:], "*") {
			return fmt.Errorf("%q: wildcard only allowed as a leading *.", e)
		}
		return nil
	}
	if strings.Contains(e, "*") {
		return fmt.Errorf("%q: wildcard only allowed as a leading *. (e.g. *.example.com)", e)
	}
	return nil
}

// parseAllowedIPs turns each allowed-ips entry into a *net.IPNet. A CIDR is parsed
// as-is; a bare IP becomes a host route (/32 for v4, /128 for v6). Empty entries and
// anything that isn't a valid IP or CIDR are rejected (fail fast, not silent).
func parseAllowedIPs(entries []string) ([]*net.IPNet, error) {
	var nets []*net.IPNet
	for _, e := range entries {
		e = strings.TrimSpace(e)
		if e == "" {
			return nil, fmt.Errorf("empty entry")
		}
		if strings.Contains(e, "/") {
			_, n, err := net.ParseCIDR(e)
			if err != nil {
				return nil, fmt.Errorf("%q is not a valid CIDR: %w", e, err)
			}
			n = canonicalizeIPNet(n)
			// Reject a default route: a /0 (incl. the v4-mapped ::ffff:0:0/96 that
			// canonicalizes to 0.0.0.0/0) would accept every destination and silently
			// turn block mode into audit mode for a whole address family. (netsec F1/F2.)
			if ones, _ := n.Mask.Size(); ones == 0 {
				return nil, fmt.Errorf("%q is a default route (/0); that disables egress filtering - list specific hosts or subnets", e)
			}
			nets = append(nets, n)
			continue
		}
		ip := net.ParseIP(e)
		if ip == nil {
			return nil, fmt.Errorf("%q is not a valid IP or CIDR", e)
		}
		if v4 := ip.To4(); v4 != nil {
			nets = append(nets, &net.IPNet{IP: v4, Mask: net.CIDRMask(32, 32)})
		} else {
			nets = append(nets, &net.IPNet{IP: ip, Mask: net.CIDRMask(128, 128)})
		}
	}
	return nets, nil
}

// canonicalizeIPNet normalizes an IPv4 (or IPv4-mapped-IPv6) network to native
// 4-byte form with a 32-bit-space mask, so a mapped form like ::ffff:0.0.0.0/96
// is seen as the 0.0.0.0/0 it really is (not hidden behind a 128-bit mask), and so
// the enforcer's To4() family split renders the correct CIDR. IPv6 is unchanged.
func canonicalizeIPNet(n *net.IPNet) *net.IPNet {
	v4 := n.IP.To4()
	if v4 == nil {
		return n
	}
	ones, bits := n.Mask.Size()
	if bits == 128 { // v4-mapped: drop the 96-bit ::ffff: prefix
		ones -= 96
		if ones < 0 {
			ones = 0
		}
	}
	return &net.IPNet{IP: v4, Mask: net.CIDRMask(ones, 32)}
}

// IsBlocking reports whether the policy actually enforces (block mode).
func (p *Policy) IsBlocking() bool { return p.Mode == ModeBlock }

// AllowsIP reports whether ip is permitted by the static allowed-ips list (any
// configured IP/CIDR contains it). Domain-resolved IPs are handled separately by
// the dynamic allow set; this is the IP/CIDR allowlist that needs no DNS.
func (p *Policy) AllowsIP(ip net.IP) bool {
	if ip == nil {
		return false
	}
	for _, n := range p.Egress.allowedNets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// AllowedIPNets returns the parsed allowed-ips CIDRs, for the enforcer to install
// as static allow-set elements. Populated by Validate.
func (p *Policy) AllowedIPNets() []*net.IPNet { return p.Egress.allowedNets }

// AllowsDomain reports whether domain is permitted by the egress allowlist.
// Matching is case-insensitive. "*.example.com" matches any single-or-multi
// label subdomain of example.com but NOT example.com itself (matching the
// conventional wildcard-cert semantics most users expect).
func (p *Policy) AllowsDomain(domain string) bool {
	domain = strings.ToLower(strings.TrimSuffix(domain, "."))
	for _, pat := range p.Egress.AllowedEndpoints {
		if matchDomain(strings.ToLower(pat), domain) {
			return true
		}
	}
	return false
}

func matchDomain(pattern, domain string) bool {
	if suffix, ok := strings.CutPrefix(pattern, "*."); ok {
		// Wildcard: domain must end with ".suffix" (a real subdomain).
		return strings.HasSuffix(domain, "."+suffix)
	}
	return pattern == domain
}

// EvalConnection decides whether a connection is allowed. It returns a non-nil
// *event.Violation when the connection breaks policy. The Blocked field is set
// by the caller (the enforcer) once it knows whether it actually dropped it.
func (p *Policy) EvalConnection(c event.Connection) *event.Violation {
	if c.Domain == "" {
		// No domain correlated: a raw-IP connection.
		if p.Egress.BlockRawIP && !p.allowsIP(c.Daddr) {
			return &event.Violation{
				Kind:   event.KindConnection,
				Reason: "raw-ip egress",
				Detail: fmt.Sprintf("%s:%d/%s by %s[%d] with no prior DNS lookup",
					c.Daddr, c.Dport, c.Proto, c.Comm, c.PID),
			}
		}
		return nil
	}
	if p.AllowsDomain(c.Domain) {
		return nil
	}
	return &event.Violation{
		Kind:   event.KindConnection,
		Reason: "domain not in allowlist",
		Detail: fmt.Sprintf("%s (%s:%d/%s) by %s[%d]",
			c.Domain, c.Daddr, c.Dport, c.Proto, c.Comm, c.PID),
	}
}

// allowsIP decides whether a raw-IP (no-domain) egress is permitted: loopback is
// always allowed (the local DNS proxy), plus any IP/CIDR the operator listed in
// allowed-ips. Used by EvalConnection so a build reaching an explicitly-allowed IP
// with no DNS lookup is not flagged as a raw-ip violation.
func (p *Policy) allowsIP(ip net.IP) bool {
	if ip == nil {
		return false
	}
	return ip.IsLoopback() || p.AllowsIP(ip)
}

// EvalFile flags writes to protected paths. Matching is prefix-based after
// expanding a leading "~" to the user's home and normalising separators.
func (p *Policy) EvalFile(f event.FileWrite) *event.Violation {
	for _, pp := range p.File.ProtectedPaths {
		if pathMatches(pp, f.Path) {
			return &event.Violation{
				Kind:   event.KindFile,
				Reason: "write to protected path",
				Detail: fmt.Sprintf("%s wrote %s (matched %q)", f.Comm, f.Path, pp),
			}
		}
	}
	return nil
}

// pathMatches reports whether a write to path hits a protected pattern. Both
// sides are canonicalized before comparison so an attacker can't slip past a
// prefix match with "..", redundant separators, or a symlink: each side is
// reduced to its filepath.Clean form AND (when it resolves on disk) its
// EvalSymlinks real path, and any candidate form of the write is matched against
// any form of the pattern.
//
// Residual (documented in SECURITY.md, tracked for the netsec re-gate): a write
// captured as a RELATIVE path (openat with a non-'/' first byte) can't be
// anchored to the process's cwd here - the eBPF layer records the raw pathname,
// not the resolved dfd/cwd - so `cd ~ && >> .ssh/authorized_keys` still evades a
// `/home/<user>/.ssh/...` pattern. Closing that fully needs capture-time cwd
// resolution in the collector. File/process policy is therefore best-effort
// detection, not an enforcement boundary.
func pathMatches(pattern, path string) bool {
	pats := canonicalForms(expandHome(pattern))
	if len(pats) == 0 {
		return false
	}
	for _, cand := range canonicalForms(path) {
		for _, pat := range pats {
			if cand == pat || strings.HasPrefix(cand, pat+"/") {
				return true
			}
		}
	}
	return false
}

// expandHome expands a leading "~" to the user's home directory.
func expandHome(p string) string {
	if home, err := os.UserHomeDir(); err == nil {
		if rest, ok := strings.CutPrefix(p, "~"); ok {
			return home + rest
		}
	}
	return p
}

// canonicalForms returns the distinct normalized forms of a path to compare:
// its filepath.Clean form, and its symlink-resolved real path when it (or, for a
// not-yet-existing target, its parent directory) resolves on disk. Trailing
// slashes are trimmed. Empty input yields no forms.
func canonicalForms(p string) []string {
	p = strings.TrimSuffix(p, "/")
	if p == "" {
		return nil
	}
	seen := map[string]struct{}{}
	var out []string
	add := func(s string) {
		s = strings.TrimSuffix(s, "/")
		if s == "" {
			return
		}
		if _, ok := seen[s]; !ok {
			seen[s] = struct{}{}
			out = append(out, s)
		}
	}
	clean := filepath.Clean(p)
	add(clean)
	if resolved, err := filepath.EvalSymlinks(clean); err == nil {
		add(resolved)
	} else if dir, base := filepath.Split(clean); dir != "" {
		// Target may not exist yet (e.g. authorized_keys about to be created);
		// resolve the parent so a symlinked directory in the path is still caught.
		if rdir, err := filepath.EvalSymlinks(strings.TrimSuffix(dir, "/")); err == nil {
			add(filepath.Join(rdir, base))
		}
	}
	return out
}

// EvalProcess flags execution of a disallowed executable. Patterns may be a
// bare name (matched against comm) or a glob path.
func (p *Policy) EvalProcess(pr event.Process) *event.Violation {
	for _, pat := range p.Process.Disallowed {
		if procMatches(pat, pr) {
			return &event.Violation{
				Kind:   event.KindProcess,
				Reason: "disallowed process",
				Detail: fmt.Sprintf("%s (%s) matched %q", pr.Comm, pr.Filename, pat),
			}
		}
	}
	return nil
}

func procMatches(pattern string, pr event.Process) bool {
	if !strings.ContainsAny(pattern, "/*") {
		return pattern == pr.Comm
	}
	ok, _ := match(pattern, pr.Filename)
	return ok
}

// match is filepath.Match but tolerant of empty inputs.
func match(pattern, name string) (bool, error) {
	if pattern == "" {
		return false, nil
	}
	// Lightweight glob: support a single trailing /* and leading *.
	if strings.HasSuffix(pattern, "/*") {
		return strings.HasPrefix(name, strings.TrimSuffix(pattern, "*")), nil
	}
	return pattern == name, nil
}
