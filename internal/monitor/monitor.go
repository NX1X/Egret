// Package monitor aggregates events from a collector.Collector into an
// event.Session, evaluating each against the policy as it arrives. It is
// deliberately platform-neutral and depends only on the collector interface and
// a Resolver, so the full run orchestration can be unit-tested with a mock
// collector - no kernel required.
package monitor

import (
	"fmt"
	"net"
	"path"
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

	overflow          uint64 // events not stored because a kind hit maxEventsPerKind
	violationOverflow uint64 // violations not stored because of maxViolations
	usedDocker        bool   // the build ran a container client (see containerClients)
}

// maxEventsPerKind caps how many connections, processes and file writes one
// session stores, and maxViolations caps the stored violations, so a build that
// opens files or connects in a tight loop cannot grow Egret's memory without
// bound. Policy evaluation still runs on every event; only storage stops, and
// each overflow is reported as a monitor violation.
const (
	maxEventsPerKind = 100_000
	maxViolations    = 10_000
)

// containerClients are programs that ask a container daemon to run work. The
// daemon, not the build, starts those containers, so they run outside the
// build cgroup and Egret does not see their traffic.
var containerClients = map[string]bool{
	"docker": true, "docker-compose": true, "docker-buildx": true,
	"podman": true, "nerdctl": true, "buildctl": true,
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

// store runs add unless the kind already holds maxEventsPerKind events. The
// caller holds m.mu.
func (m *Monitor) store(n int, add func()) {
	if n >= maxEventsPerKind {
		m.overflow++
		return
	}
	add()
}

// addViolation stores v unless maxViolations are already stored. The caller
// holds m.mu.
func (m *Monitor) addViolation(v event.Violation) {
	if len(m.session.Violations) >= maxViolations {
		m.violationOverflow++
		return
	}
	m.session.Violations = append(m.session.Violations, v)
}

// Coverage describes how much of the build the probes could see. Fill it after
// the collector is closed.
type Coverage struct {
	// Scoped is true when the probes recorded only the build cgroup.
	Scoped bool
	// KernelDropped is the number of events lost in full ring buffers.
	KernelDropped uint64
	// DropCountErr is set when the loss count could not be read in full.
	DropCountErr error
	// Gaps from the collector (for example a probe fallback); each becomes a
	// monitor violation, so fail-on-violations trips on a blind spot.
	Gaps []string
}

// Finish adds the coverage findings to the session returned by Wait:
//   - lost events (kernel drops plus events over the storage cap) are a
//     monitor violation, because the report then misses part of the build;
//   - a scoped run that recorded no exec at all is a monitor violation: the
//     build always execs at least once, so the scope matched nothing;
//   - an unscoped run gets a note that the report includes other processes;
//   - a build that ran a container client gets a note that container traffic
//     is not covered.
func (m *Monitor) Finish(cov Coverage) *event.Session {
	m.mu.Lock()
	defer m.mu.Unlock()
	s := m.session
	if lost := cov.KernelDropped + m.overflow; lost > 0 {
		s.Violations = append(s.Violations, event.Violation{
			Kind:   event.KindMonitor,
			Reason: "events lost",
			Detail: fmt.Sprintf("%d event(s) were not recorded (%d lost in full kernel buffers, %d over the %d-per-kind storage cap); this report is incomplete",
				lost, cov.KernelDropped, m.overflow, maxEventsPerKind),
		})
	}
	if cov.DropCountErr != nil {
		s.Violations = append(s.Violations, event.Violation{
			Kind:   event.KindMonitor,
			Reason: "event loss unknown",
			Detail: "Egret could not read its lost-event counter (" + cov.DropCountErr.Error() + "), so this report may be incomplete without saying so",
		})
	}
	if m.violationOverflow > 0 {
		s.Violations = append(s.Violations, event.Violation{
			Kind:   event.KindMonitor,
			Reason: "violations not stored",
			Detail: fmt.Sprintf("%d more violation(s) were found but not stored (cap %d); this report lists only the first ones", m.violationOverflow, maxViolations),
		})
	}
	if cov.Scoped && len(s.Processes) == 0 {
		s.Violations = append(s.Violations, event.Violation{
			Kind:   event.KindMonitor,
			Reason: "scope recorded nothing",
			Detail: "the probes saw no exec from the build cgroup, so this report may miss the whole build",
		})
	}
	for _, g := range cov.Gaps {
		s.Violations = append(s.Violations, event.Violation{Kind: event.KindMonitor, Reason: "probe coverage gap", Detail: g})
	}
	if !cov.Scoped {
		s.Notes = append(s.Notes, "Not scoped to the build: Egret could not create a build cgroup or start the build in it, so this report includes every process on the host.")
	}
	if m.usedDocker {
		s.Notes = append(s.Notes, "The build used a container client (for example docker). Containers are started by the container daemon, outside the build, so their traffic is not in this report.")
	}
	return s
}

func (m *Monitor) drainConns() {
	defer m.wg.Done()
	for c := range m.coll.Connections() {
		if c.Domain == "" {
			c.Domain = m.res.DomainForIP(c.Daddr)
		}
		m.mu.Lock()
		m.store(len(m.session.Connections), func() { m.session.Connections = append(m.session.Connections, c) })
		if v := m.pol.EvalConnection(c); v != nil {
			v.Blocked = m.pol.IsBlocking()
			m.addViolation(*v)
		}
		m.mu.Unlock()
	}
}

func (m *Monitor) drainProcs() {
	defer m.wg.Done()
	for p := range m.coll.Processes() {
		m.mu.Lock()
		m.store(len(m.session.Processes), func() { m.session.Processes = append(m.session.Processes, p) })
		// Match the process name too: an exec through a file descriptor
		// (fexecve, execveat with AT_EMPTY_PATH) has a /dev/fd/N filename.
		if containerClients[path.Base(p.Filename)] || containerClients[p.Comm] {
			m.usedDocker = true
		}
		if v := m.pol.EvalProcess(p); v != nil {
			m.addViolation(*v)
		}
		m.mu.Unlock()
	}
}

func (m *Monitor) drainFiles() {
	defer m.wg.Done()
	for w := range m.coll.FileWrites() {
		m.mu.Lock()
		m.store(len(m.session.FileWrites), func() { m.session.FileWrites = append(m.session.FileWrites, w) })
		if v := m.pol.EvalFile(w); v != nil {
			m.addViolation(*v)
		}
		m.mu.Unlock()
	}
}
