package enforcer

import (
	"net"
	"testing"

	"github.com/NX1X/Egret/internal/policy"
	"github.com/miekg/dns"
)

// captureWriter is a minimal dns.ResponseWriter that records the reply.
type captureWriter struct{ msg *dns.Msg }

func (w *captureWriter) LocalAddr() net.Addr       { return &net.UDPAddr{} }
func (w *captureWriter) RemoteAddr() net.Addr      { return &net.UDPAddr{} }
func (w *captureWriter) WriteMsg(m *dns.Msg) error { w.msg = m; return nil }
func (w *captureWriter) Write([]byte) (int, error) { return 0, nil }
func (w *captureWriter) Close() error              { return nil }
func (w *captureWriter) TsigStatus() error         { return nil }
func (w *captureWriter) TsigTimersOnly(bool)       {}
func (w *captureWriter) Hijack()                   {}

func TestRecordAnswers(t *testing.T) {
	p := NewDNSProxy(policy.Default(), nil)

	resp := new(dns.Msg)
	resp.Answer = []dns.RR{
		&dns.A{A: net.IPv4(140, 82, 121, 4)},
		&dns.AAAA{AAAA: net.ParseIP("2606:50c0::153")},
		&dns.CNAME{Target: "ignored."}, // non-address records are skipped
	}

	ips, ttl := p.recordAnswers("github.com", resp)
	if len(ips) != 2 {
		t.Fatalf("recordAnswers returned %d IPs, want 2", len(ips))
	}
	// The answer TTLs are 0, which must clamp up to the floor (not stay 0, which
	// would let a rebinding answer refresh a 0s allowance forever).
	if ttl != minAllowTTL {
		t.Errorf("clamped ttl = %d, want floor %d", ttl, minAllowTTL)
	}
	if d := p.DomainForIP(net.IPv4(140, 82, 121, 4)); d != "github.com" {
		t.Errorf("DomainForIP(v4) = %q, want github.com", d)
	}
	if d := p.DomainForIP(net.ParseIP("2606:50c0::153")); d != "github.com" {
		t.Errorf("DomainForIP(v6) = %q, want github.com", d)
	}
	if d := p.DomainForIP(net.IPv4(1, 2, 3, 4)); d != "" {
		t.Errorf("unknown IP should resolve to empty, got %q", d)
	}
	if d := p.DomainForIP(nil); d != "" {
		t.Errorf("nil IP should resolve to empty, got %q", d)
	}
}

func TestHandleRefusesUnallowlistedInBlockMode(t *testing.T) {
	pol := &policy.Policy{
		Mode:   policy.ModeBlock,
		Egress: policy.Egress{AllowedEndpoints: []string{"github.com"}},
	}
	p := NewDNSProxy(pol, nil)

	req := new(dns.Msg)
	req.SetQuestion("evil.example.com.", dns.TypeA)

	w := &captureWriter{}
	p.handle(w, req)

	if w.msg == nil {
		t.Fatal("no reply written")
	}
	if w.msg.Rcode != dns.RcodeRefused {
		t.Errorf("Rcode = %d, want REFUSED (%d) for non-allowlisted name in block mode",
			w.msg.Rcode, dns.RcodeRefused)
	}
}

func TestHandleEmptyQuestion(t *testing.T) {
	p := NewDNSProxy(policy.Default(), nil)
	w := &captureWriter{}
	p.handle(w, new(dns.Msg))
	if w.msg == nil || w.msg.Rcode != dns.RcodeRefused {
		t.Errorf("empty question should be refused, got %+v", w.msg)
	}
}

func TestNoopFirewallAndDomainForIP(t *testing.T) {
	// Audit-mode enforcer uses the noop firewall and still correlates domains.
	e, err := New(policy.Default())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if e.ListenAddr() == "" {
		t.Error("ListenAddr should be set")
	}
	// noopFirewall accepts everything without error.
	if err := e.fw.Setup(nil); err != nil {
		t.Errorf("noop Setup: %v", err)
	}
	if err := e.fw.AllowIPs("x", []net.IP{net.IPv4(1, 1, 1, 1)}, 300); err != nil {
		t.Errorf("noop AllowIPs: %v", err)
	}
	if fd := e.BuildCgroupFD(); fd != -1 {
		t.Errorf("audit-mode BuildCgroupFD = %d, want -1", fd)
	}
	if err := e.fw.Teardown(); err != nil {
		t.Errorf("noop Teardown: %v", err)
	}
}
