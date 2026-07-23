package policy

import (
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/NX1X/Egret/internal/event"
)

func TestDefault(t *testing.T) {
	p := Default()
	if p.Version != SupportedVersion {
		t.Errorf("version = %d, want %d", p.Version, SupportedVersion)
	}
	if p.Mode != ModeAudit {
		t.Errorf("mode = %q, want audit (safe default)", p.Mode)
	}
	if !p.Egress.BlockRawIP {
		t.Error("block-raw-ip should default true")
	}
	if err := p.Validate(); err != nil {
		t.Errorf("default policy should validate: %v", err)
	}
}

func TestAllowsDomain(t *testing.T) {
	p := &Policy{Egress: Egress{AllowedEndpoints: []string{
		"github.com",
		"api.github.com",
		"*.actions.githubusercontent.com",
		"Registry.NPMjs.org", // mixed case on purpose
	}}}

	tests := []struct {
		domain string
		want   bool
	}{
		{"github.com", true},
		{"GitHub.com", true},  // case-insensitive
		{"github.com.", true}, // trailing dot tolerated
		{"api.github.com", true},
		{"unknown.com", false},
		{"notgithub.com", false},
		{"foo.actions.githubusercontent.com", true},
		{"a.b.actions.githubusercontent.com", true},
		{"actions.githubusercontent.com", false}, // wildcard != apex
		{"registry.npmjs.org", true},             // matched despite case in pattern
		{"evil.github.com", false},               // exact entry, not a wildcard
	}
	for _, tc := range tests {
		if got := p.AllowsDomain(tc.domain); got != tc.want {
			t.Errorf("AllowsDomain(%q) = %v, want %v", tc.domain, got, tc.want)
		}
	}
}

func TestAllowsIP(t *testing.T) {
	p := &Policy{Version: SupportedVersion, Mode: ModeBlock, Egress: Egress{AllowedIPs: []string{
		"10.0.0.5",           // bare v4 host
		"192.168.0.0/16",     // v4 CIDR
		"2001:db8::1",        // bare v6 host
		"2001:db8:cafe::/48", // v6 CIDR
	}}}
	if err := p.Validate(); err != nil { // Validate parses the entries into CIDRs
		t.Fatalf("valid allowed-ips should validate: %v", err)
	}

	tests := []struct {
		ip   string
		want bool
	}{
		{"10.0.0.5", true},          // exact host
		{"10.0.0.6", false},         // adjacent host not allowed (it was a /32)
		{"192.168.1.1", true},       // inside the /16
		{"192.169.0.1", false},      // outside the /16
		{"2001:db8::1", true},       // exact v6 host
		{"2001:db8:cafe::99", true}, // inside the v6 /48
		{"2001:db8:beef::1", false}, // outside the v6 /48
		{"8.8.8.8", false},          // unrelated
	}
	for _, tc := range tests {
		if got := p.AllowsIP(net.ParseIP(tc.ip)); got != tc.want {
			t.Errorf("AllowsIP(%s) = %v, want %v", tc.ip, got, tc.want)
		}
	}
	if p.AllowsIP(nil) {
		t.Error("AllowsIP(nil) should be false")
	}
	// AllowedIPNets exposes the parsed set for the enforcer.
	if len(p.AllowedIPNets()) != 4 {
		t.Errorf("AllowedIPNets len = %d, want 4", len(p.AllowedIPNets()))
	}
}

func TestValidateRejectsBadAllowedIPs(t *testing.T) {
	bad := []string{
		"not-an-ip", "10.0.0.0/999", "", "example.com", "10.0.0.1:80",
		"0.0.0.0/0",         // default route disables v4 filtering (netsec F1)
		"::/0",              // default route disables v6 filtering
		"::ffff:0.0.0.0/96", // v4-mapped form of 0.0.0.0/0 (netsec F2)
	}
	for _, b := range bad {
		p := &Policy{Version: SupportedVersion, Mode: ModeBlock, Egress: Egress{AllowedIPs: []string{b}}}
		if err := p.Validate(); err == nil {
			t.Errorf("allowed-ips %q should be rejected", b)
		}
	}
}

// TestAllowedIPsV4MappedCanonicalized: a v4-mapped IPv6 host is stored as native v4
// so the enforcer's family split and matching are correct (netsec F2).
func TestAllowedIPsV4MappedCanonicalized(t *testing.T) {
	p := &Policy{Version: SupportedVersion, Mode: ModeBlock,
		Egress: Egress{AllowedIPs: []string{"::ffff:10.0.0.1"}}}
	if err := p.Validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}
	nets := p.AllowedIPNets()
	if len(nets) != 1 || nets[0].IP.To4() == nil {
		t.Fatalf("v4-mapped entry should canonicalize to native v4, got %v", nets)
	}
	if !p.AllowsIP(net.ParseIP("10.0.0.1")) {
		t.Error("canonicalized v4 host should match its v4 form")
	}
}

func TestValidate(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(*Policy)
		wantErr string
	}{
		{"ok", func(*Policy) {}, ""},
		{"bad version", func(p *Policy) { p.Version = 2 }, "version"},
		{"bad mode", func(p *Policy) { p.Mode = "enforce" }, "mode"},
		{"endpoint with scheme", func(p *Policy) {
			p.Egress.AllowedEndpoints = []string{"https://github.com"}
		}, "bare domain"},
		{"endpoint with port", func(p *Policy) {
			p.Egress.AllowedEndpoints = []string{"github.com:443"}
		}, "bare domain"},
		{"bare wildcard", func(p *Policy) {
			p.Egress.AllowedEndpoints = []string{"*"}
		}, "too broad"},
		{"mid wildcard", func(p *Policy) {
			p.Egress.AllowedEndpoints = []string{"foo.*.com"}
		}, "leading"},
		{"bad report format", func(p *Policy) {
			p.Report.Format = []string{"pdf"}
		}, "report.format"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p := Default()
			tc.mutate(p)
			err := p.Validate()
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("error = %v, want containing %q", err, tc.wantErr)
			}
		})
	}
}

func TestLoad(t *testing.T) {
	dir := t.TempDir()

	valid := filepath.Join(dir, "ok.yaml")
	os.WriteFile(valid, []byte(`
version: 1
mode: block
egress:
  allowed-endpoints: [github.com, "*.example.com"]
  block-raw-ip: true
filesystem:
  protected-paths: ["/etc/"]
`), 0o644)

	p, err := Load(valid)
	if err != nil {
		t.Fatalf("Load valid: %v", err)
	}
	if p.Mode != ModeBlock {
		t.Errorf("mode = %q, want block", p.Mode)
	}
	if len(p.Egress.AllowedEndpoints) != 2 {
		t.Errorf("endpoints = %v", p.Egress.AllowedEndpoints)
	}
	// Report defaults must survive a partial file.
	if p.Report.OutputDir == "" {
		t.Error("report defaults should be applied when omitted")
	}

	if _, err := Load(filepath.Join(dir, "missing.yaml")); err == nil {
		t.Error("expected error for missing file")
	}

	bad := filepath.Join(dir, "bad.yaml")
	os.WriteFile(bad, []byte("version: 1\nmode: [oops"), 0o644)
	if _, err := Load(bad); err == nil {
		t.Error("expected parse error for malformed yaml")
	}

	invalid := filepath.Join(dir, "invalid.yaml")
	os.WriteFile(invalid, []byte("version: 9\n"), 0o644)
	if _, err := Load(invalid); err == nil {
		t.Error("expected validation error for version 9")
	}
}

func TestEvalConnection(t *testing.T) {
	p := &Policy{
		Mode:   ModeBlock,
		Egress: Egress{AllowedEndpoints: []string{"github.com"}, BlockRawIP: true},
	}
	tests := []struct {
		name    string
		conn    event.Connection
		wantErr bool
	}{
		{"allowed domain", event.Connection{Domain: "github.com", Daddr: net.IPv4(1, 1, 1, 1)}, false},
		{"blocked domain", event.Connection{Domain: "evil.com", Daddr: net.IPv4(2, 2, 2, 2)}, true},
		{"raw ip blocked", event.Connection{Daddr: net.IPv4(8, 8, 8, 8), Dport: 443}, true},
		{"loopback allowed", event.Connection{Daddr: net.IPv4(127, 0, 0, 1)}, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			v := p.EvalConnection(tc.conn)
			if (v != nil) != tc.wantErr {
				t.Fatalf("EvalConnection violation=%v, wantViolation=%v", v, tc.wantErr)
			}
		})
	}

	// With block-raw-ip disabled, raw IPs are allowed.
	p2 := &Policy{Egress: Egress{BlockRawIP: false}}
	if v := p2.EvalConnection(event.Connection{Daddr: net.IPv4(8, 8, 8, 8)}); v != nil {
		t.Errorf("raw IP should be allowed when block-raw-ip is false, got %v", v)
	}

	// A raw IP inside allowed-ips is NOT a violation even with block-raw-ip on.
	p3 := &Policy{Version: SupportedVersion, Mode: ModeBlock,
		Egress: Egress{BlockRawIP: true, AllowedIPs: []string{"203.0.113.0/24"}}}
	if err := p3.Validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}
	if v := p3.EvalConnection(event.Connection{Daddr: net.ParseIP("203.0.113.7"), Dport: 443}); v != nil {
		t.Errorf("allowed-ips raw IP should be permitted, got violation %v", v)
	}
	if v := p3.EvalConnection(event.Connection{Daddr: net.ParseIP("8.8.8.8"), Dport: 443}); v == nil {
		t.Error("a raw IP outside allowed-ips should still be a violation")
	}
}

func TestEvalFile(t *testing.T) {
	p := &Policy{File: File{ProtectedPaths: []string{"/etc/", ".git/", "~/.ssh/"}}}
	home, _ := os.UserHomeDir()

	tests := []struct {
		path string
		want bool
	}{
		{"/etc/passwd", true},
		{"/etc", true}, // exact dir
		{".git/config", true},
		{"/var/log/app.log", false},
		{home + "/.ssh/id_rsa", true},      // ~ expands to the user's home dir
		{"/etc/../etc/passwd", true},       // ".." traversal is canonicalized before matching
		{"/etc/../var/log/app.log", false}, // ".." that escapes /etc must NOT match
	}
	for _, tc := range tests {
		got := p.EvalFile(event.FileWrite{Path: tc.path}) != nil
		if got != tc.want {
			t.Errorf("EvalFile(%q) violation=%v, want %v", tc.path, got, tc.want)
		}
	}
}

func TestEvalProcess(t *testing.T) {
	p := &Policy{Process: Proc{Disallowed: []string{"nc", "/tmp/*"}}}
	tests := []struct {
		proc event.Process
		want bool
	}{
		{event.Process{Comm: "nc"}, true},
		{event.Process{Comm: "bash"}, false},
		{event.Process{Comm: "x", Filename: "/tmp/payload"}, true},
		{event.Process{Comm: "x", Filename: "/usr/bin/curl"}, false},
	}
	for _, tc := range tests {
		got := p.EvalProcess(tc.proc) != nil
		if got != tc.want {
			t.Errorf("EvalProcess(%+v) violation=%v, want %v", tc.proc, got, tc.want)
		}
	}
}

func TestIsBlocking(t *testing.T) {
	if (&Policy{Mode: ModeBlock}).IsBlocking() != true {
		t.Error("block mode should be blocking")
	}
	if (&Policy{Mode: ModeAudit}).IsBlocking() != false {
		t.Error("audit mode should not be blocking")
	}
}

func TestExtendsLocal(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "base.yaml"), []byte(`
version: 1
mode: block
egress:
  allowed-endpoints: [github.com, api.github.com]
  block-raw-ip: true
filesystem:
  protected-paths: ["/etc/"]
`), 0o644)
	child := filepath.Join(dir, "child.yaml")
	os.WriteFile(child, []byte(`
version: 1
extends: base.yaml
mode: audit
egress:
  allowed-endpoints: [registry.npmjs.org]
  block-raw-ip: false
`), 0o644)

	p, err := Load(child)
	if err != nil {
		t.Fatalf("Load extends: %v", err)
	}
	// Scalar override: child wins (mode + block-raw-ip:false).
	if p.Mode != ModeAudit {
		t.Errorf("mode = %q, want audit (child override)", p.Mode)
	}
	if p.Egress.BlockRawIP {
		t.Error("block-raw-ip should be false (child override of base true)")
	}
	// Lists unioned: base ∪ child.
	if !p.AllowsDomain("github.com") || !p.AllowsDomain("api.github.com") || !p.AllowsDomain("registry.npmjs.org") {
		t.Errorf("allowed-endpoints not unioned: %v", p.Egress.AllowedEndpoints)
	}
	if len(p.Egress.AllowedEndpoints) != 3 {
		t.Errorf("endpoints = %v, want 3 unioned", p.Egress.AllowedEndpoints)
	}
	if len(p.File.ProtectedPaths) != 1 || p.File.ProtectedPaths[0] != "/etc/" {
		t.Errorf("protected-paths = %v, want inherited [/etc/]", p.File.ProtectedPaths)
	}
	if p.Extends != "" {
		t.Errorf("Extends should be cleared, got %q", p.Extends)
	}
}

func TestExtendsRejectsTraversalOutsideBaseDir(t *testing.T) {
	root := t.TempDir()
	// A sensitive file OUTSIDE the policy directory.
	secretDir := t.TempDir()
	os.WriteFile(filepath.Join(secretDir, "secret.yaml"), []byte("version: 1\nmode: block\n"), 0o644)

	policyDir := filepath.Join(root, "repo")
	os.MkdirAll(policyDir, 0o755)
	child := filepath.Join(policyDir, "child.yaml")

	// Relative traversal that escapes the policy directory must be rejected.
	rel, _ := filepath.Rel(policyDir, filepath.Join(secretDir, "secret.yaml"))
	os.WriteFile(child, []byte("version: 1\nextends: "+rel+"\nmode: audit\n"), 0o644)
	if _, err := Load(child); err == nil {
		t.Error("extends escaping the policy dir via .. should be rejected")
	}

	// An absolute extends path must also be rejected.
	os.WriteFile(child, []byte("version: 1\nextends: "+filepath.Join(secretDir, "secret.yaml")+"\nmode: audit\n"), 0o644)
	if _, err := Load(child); err == nil {
		t.Error("absolute extends path should be rejected")
	}
}

func TestUnknownPolicyFieldRejected(t *testing.T) {
	dir := t.TempDir()
	// `allow-endpoints` is a typo for `allowed-endpoints`; strict decoding must
	// fail fast rather than silently drop the intended allowlist.
	p := filepath.Join(dir, "typo.yaml")
	os.WriteFile(p, []byte("version: 1\nmode: block\negress:\n  allow-endpoints: [github.com]\n"), 0o644)
	if _, err := Load(p); err == nil {
		t.Error("unknown/misspelled policy field should be rejected by strict decode")
	}
}

func TestExtendsRemoteNeedsResolver(t *testing.T) {
	dir := t.TempDir()
	child := filepath.Join(dir, "c.yaml")
	os.WriteFile(child, []byte("version: 1\nextends: org://acme/base\nmode: audit\n"), 0o644)
	if _, err := Load(child); err == nil {
		t.Error("remote extends with no resolver should error")
	}
}
