// Package monitor aggregates events from a collector.Collector into an
// event.Session, evaluating each against the policy as it arrives. It is
// deliberately platform-neutral and depends only on the collector interface and
// a Resolver, so the full run orchestration can be unit-tested with a mock
// collector - no kernel required.
package monitor

import (
	"net"
	"sync"

	"github.com/NX1X/Egret/internal/event"
	"github.com/NX1X/Egret/internal/policy"
)

// Source is the stream of kernel events the monitor drains. It is satisfied by
// *collector.LinuxCollector (and by mocks). Declaring the interface here - at
// the consumer - keeps this package free of the eBPF/collector dependency, so
// it compiles and tests on any platform without generated bindings.
type Source interface {
	Connections() <-chan event.Connection
	Processes() <-chan event.Process
	FileWrites() <-chan event.FileWrite
}

// Resolver maps a destination IP back to the domain it was observed to resolve
// to (satisfied by the enforcer's DNS proxy). A nil/empty result means the
// connection had no correlated domain (a raw-IP connection).
type Resolver interface {
	DomainForIP(net.IP) string
}

// NopResolver never correlates a domain. Used in tests and when no DNS proxy
// is wired up.
type NopResolver struct{}

func (NopResolver) DomainForIP(net.IP) string { return "" }

// Monitor drains a Source's event channels into a session.
type Monitor struct {
	coll Source
	pol  *policy.Policy
	res  Resolver

	mu      sync.Mutex
	session *event.Session
	wg      sync.WaitGroup
}

// New builds a Monitor. The session's Mode is set from the policy; the caller
// fills the remaining metadata (Command, timing, ExitCode) on the value
// returned by Wait.
func New(coll Source, pol *policy.Policy, res Resolver) *Monitor {
	if res == nil {
		res = NopResolver{}
	}
	return &Monitor{
		coll:    coll,
		pol:     pol,
		res:     res,
		session: &event.Session{Mode: string(pol.Mode)},
	}
}

// Start launches the drain goroutines. They run until the collector's channels
// are closed (which the collector does on Close / context cancellation).
func (m *Monitor) Start() {
	m.wg.Add(3)
	go m.drainConns()
	go m.drainProcs()
	go m.drainFiles()
}

// Wait blocks until every event channel is drained and closed, then returns the
// accumulated session.
func (m *Monitor) Wait() *event.Session {
	m.wg.Wait()
	return m.session
}

func (m *Monitor) drainConns() {
	defer m.wg.Done()
	for c := range m.coll.Connections() {
		if c.Domain == "" {
			c.Domain = m.res.DomainForIP(c.Daddr)
		}
		m.mu.Lock()
		m.session.Connections = append(m.session.Connections, c)
		if v := m.pol.EvalConnection(c); v != nil {
			v.Blocked = m.pol.IsBlocking()
			m.session.Violations = append(m.session.Violations, *v)
		}
		m.mu.Unlock()
	}
}

func (m *Monitor) drainProcs() {
	defer m.wg.Done()
	for p := range m.coll.Processes() {
		m.mu.Lock()
		m.session.Processes = append(m.session.Processes, p)
		if v := m.pol.EvalProcess(p); v != nil {
			m.session.Violations = append(m.session.Violations, *v)
		}
		m.mu.Unlock()
	}
}

func (m *Monitor) drainFiles() {
	defer m.wg.Done()
	for w := range m.coll.FileWrites() {
		m.mu.Lock()
		m.session.FileWrites = append(m.session.FileWrites, w)
		if v := m.pol.EvalFile(w); v != nil {
			m.session.Violations = append(m.session.Violations, *v)
		}
		m.mu.Unlock()
	}
}
