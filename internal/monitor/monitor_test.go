package monitor

import (
	"net"
	"testing"

	"github.com/NX1X/Egret/internal/event"
	"github.com/NX1X/Egret/internal/policy"
)

// fakeCollector implements collector.Collector over preloaded channels, letting
// the orchestration be tested with no kernel/eBPF.
type fakeCollector struct {
	conns  chan event.Connection
	procs  chan event.Process
	writes chan event.FileWrite
}

func newFakeCollector(c []event.Connection, p []event.Process, w []event.FileWrite) *fakeCollector {
	f := &fakeCollector{
		conns:  make(chan event.Connection, len(c)+1),
		procs:  make(chan event.Process, len(p)+1),
		writes: make(chan event.FileWrite, len(w)+1),
	}
	for _, x := range c {
		f.conns <- x
	}
	for _, x := range p {
		f.procs <- x
	}
	for _, x := range w {
		f.writes <- x
	}
	// Sender is done: closing lets the drains terminate.
	close(f.conns)
	close(f.procs)
	close(f.writes)
	return f
}

func (f *fakeCollector) Connections() <-chan event.Connection { return f.conns }
func (f *fakeCollector) Processes() <-chan event.Process      { return f.procs }
func (f *fakeCollector) FileWrites() <-chan event.FileWrite   { return f.writes }
func (f *fakeCollector) Close() error                         { return nil }

// fakeResolver maps IP string -> domain.
type fakeResolver map[string]string

func (r fakeResolver) DomainForIP(ip net.IP) string {
	if ip == nil {
		return ""
	}
	return r[ip.String()]
}

func TestMonitorAggregatesAndEvaluates(t *testing.T) {
	pol := &policy.Policy{
		Mode: policy.ModeBlock,
		Egress: policy.Egress{
			AllowedEndpoints: []string{"github.com"},
			BlockRawIP:       true,
		},
		File:    policy.File{ProtectedPaths: []string{"/etc/"}},
		Process: policy.Proc{Disallowed: []string{"nc"}},
	}

	conns := []event.Connection{
		{Comm: "git", Domain: "github.com", Daddr: net.IPv4(1, 1, 1, 1)}, // allowed (explicit domain)
		{Comm: "curl", Daddr: net.IPv4(9, 9, 9, 9)},                      // correlated -> github.com -> allowed
		{Comm: "x", Daddr: net.IPv4(8, 8, 8, 8), Dport: 53},              // raw IP -> violation
	}
	procs := []event.Process{{Comm: "nc"}, {Comm: "bash"}}
	writes := []event.FileWrite{{Comm: "sh", Path: "/etc/passwd"}, {Comm: "sh", Path: "/tmp/ok"}}

	res := fakeResolver{"9.9.9.9": "github.com"}
	mon := New(newFakeCollector(conns, procs, writes), pol, res)
	mon.Start()
	s := mon.Wait()

	if len(s.Connections) != 3 {
		t.Errorf("connections = %d, want 3", len(s.Connections))
	}
	// The correlated connection should have its Domain backfilled.
	var correlated *event.Connection
	for i := range s.Connections {
		if s.Connections[i].Daddr.Equal(net.IPv4(9, 9, 9, 9)) {
			correlated = &s.Connections[i]
		}
	}
	if correlated == nil || correlated.Domain != "github.com" {
		t.Errorf("expected 9.9.9.9 correlated to github.com, got %+v", correlated)
	}

	// Violations: raw-IP conn + disallowed proc + protected file = 3.
	if len(s.Violations) != 3 {
		t.Fatalf("violations = %d, want 3: %+v", len(s.Violations), s.Violations)
	}

	// The connection violation must be marked blocked in block mode.
	var connViol *event.Violation
	for i := range s.Violations {
		if s.Violations[i].Kind == event.KindConnection {
			connViol = &s.Violations[i]
		}
	}
	if connViol == nil || !connViol.Blocked {
		t.Errorf("connection violation should be blocked in block mode: %+v", connViol)
	}

	if s.Mode != string(policy.ModeBlock) {
		t.Errorf("session mode = %q, want block", s.Mode)
	}
}

func TestMonitorNilResolverUsesNop(t *testing.T) {
	pol := policy.Default() // audit mode, block-raw-ip true
	conns := []event.Connection{{Daddr: net.IPv4(8, 8, 8, 8)}}
	mon := New(newFakeCollector(conns, nil, nil), pol, nil)
	mon.Start()
	s := mon.Wait()

	// In audit mode the raw IP is still flagged (logged, not blocked).
	if len(s.Violations) != 1 || s.Violations[0].Blocked {
		t.Errorf("audit raw-IP should be flagged-not-blocked, got %+v", s.Violations)
	}
}

func TestNopResolver(t *testing.T) {
	if (NopResolver{}).DomainForIP(net.IPv4(1, 2, 3, 4)) != "" {
		t.Error("NopResolver should never resolve")
	}
}
