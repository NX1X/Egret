package monitor

import (
	"errors"
	"strings"
	"testing"

	"github.com/NX1X/Egret/internal/event"
	"github.com/NX1X/Egret/internal/policy"
)

func runMonitor(t *testing.T, procs []event.Process, writes []event.FileWrite, cov Coverage) *event.Session {
	t.Helper()
	m := New(newFakeCollector(nil, procs, writes), policy.Default(), nil)
	m.Start()
	m.Wait()
	return m.Finish(cov)
}

func monitorViolations(s *event.Session) []event.Violation {
	var out []event.Violation
	for _, v := range s.Violations {
		if v.Kind == event.KindMonitor {
			out = append(out, v)
		}
	}
	return out
}

func TestFinishCleanScopedRun(t *testing.T) {
	s := runMonitor(t, []event.Process{{PID: 10, Filename: "/usr/bin/make"}}, nil, Coverage{Scoped: true})
	if v := monitorViolations(s); len(v) != 0 {
		t.Errorf("clean scoped run has monitor violations: %+v", v)
	}
	if len(s.Notes) != 0 {
		t.Errorf("clean scoped run has notes: %q", s.Notes)
	}
}

func TestFinishReportsKernelDrops(t *testing.T) {
	s := runMonitor(t, []event.Process{{PID: 10, Filename: "/bin/sh"}}, nil, Coverage{Scoped: true, KernelDropped: 7})
	v := monitorViolations(s)
	if len(v) != 1 || v[0].Reason != "events lost" || !strings.Contains(v[0].Detail, "7 lost in full kernel buffers") {
		t.Fatalf("want one 'events lost' violation naming 7 kernel drops, got %+v", v)
	}
}

// A scope that matched nothing must not look like a clean run.
func TestFinishFlagsEmptyScope(t *testing.T) {
	s := runMonitor(t, nil, nil, Coverage{Scoped: true})
	v := monitorViolations(s)
	if len(v) != 1 || v[0].Reason != "scope recorded nothing" {
		t.Fatalf("want a 'scope recorded nothing' violation, got %+v", v)
	}
}

func TestFinishNotesUnscopedRun(t *testing.T) {
	s := runMonitor(t, nil, nil, Coverage{Scoped: false})
	if v := monitorViolations(s); len(v) != 0 {
		t.Errorf("an unscoped run with no exec is not a scope failure: %+v", v)
	}
	if len(s.Notes) != 1 || !strings.Contains(s.Notes[0], "every process on the host") {
		t.Errorf("want the unscoped note, got %q", s.Notes)
	}
}

func TestFinishNotesContainerClient(t *testing.T) {
	procs := []event.Process{{PID: 10, Filename: "/bin/sh"}, {PID: 11, Filename: "/usr/bin/docker"}}
	s := runMonitor(t, procs, nil, Coverage{Scoped: true})
	if len(s.Notes) != 1 || !strings.Contains(s.Notes[0], "container client") {
		t.Errorf("want the container note, got %q", s.Notes)
	}
	// A path that only contains "docker" is not a container client.
	s = runMonitor(t, []event.Process{{PID: 10, Filename: "/opt/dockerfile-lint"}}, nil, Coverage{Scoped: true})
	if len(s.Notes) != 0 {
		t.Errorf("dockerfile-lint is not a container client, got notes %q", s.Notes)
	}
}

func TestStorageCapCountsOverflow(t *testing.T) {
	writes := make([]event.FileWrite, maxEventsPerKind+5)
	for i := range writes {
		writes[i] = event.FileWrite{PID: 1, Path: "/tmp/x"}
	}
	s := runMonitor(t, []event.Process{{PID: 1, Filename: "/bin/sh"}}, writes, Coverage{Scoped: true})
	if len(s.FileWrites) != maxEventsPerKind {
		t.Errorf("stored %d file writes, want the cap %d", len(s.FileWrites), maxEventsPerKind)
	}
	v := monitorViolations(s)
	if len(v) != 1 || !strings.Contains(v[0].Detail, "5 over the") {
		t.Fatalf("want an 'events lost' violation counting 5 over the cap, got %+v", v)
	}
}

func TestFinishReportsUnreadableDropCounter(t *testing.T) {
	s := runMonitor(t, []event.Process{{PID: 1, Filename: "/bin/sh"}}, nil,
		Coverage{Scoped: true, DropCountErr: errors.New("map lookup failed")})
	v := monitorViolations(s)
	if len(v) != 1 || v[0].Reason != "event loss unknown" {
		t.Fatalf("want an 'event loss unknown' violation, got %+v", v)
	}
}

func TestViolationCap(t *testing.T) {
	// Every write to a protected path is a violation under the default policy.
	writes := make([]event.FileWrite, maxViolations+3)
	for i := range writes {
		writes[i] = event.FileWrite{PID: 1, Path: "/etc/passwd"}
	}
	pol := policy.Default()
	pol.File.ProtectedPaths = []string{"/etc/"}
	m := New(newFakeCollector(nil, []event.Process{{PID: 1, Filename: "/bin/sh"}}, writes), pol, nil)
	m.Start()
	m.Wait()
	s := m.Finish(Coverage{Scoped: true})
	var capped *event.Violation
	n := 0
	for i, v := range s.Violations {
		if v.Kind == event.KindFile {
			n++
		}
		if v.Reason == "violations not stored" {
			capped = &s.Violations[i]
		}
	}
	if n != maxViolations {
		t.Errorf("stored %d file violations, want the cap %d", n, maxViolations)
	}
	if capped == nil || !strings.Contains(capped.Detail, "3 more violation") {
		t.Fatalf("want a 'violations not stored' violation counting 3, got %+v", capped)
	}
}
