package event

import (
	"net"
	"strings"
	"testing"
	"time"
)

func TestConnectionString(t *testing.T) {
	c := Connection{PID: 42, Comm: "curl", Daddr: net.IPv4(140, 82, 121, 4), Dport: 443, Proto: "tcp"}
	if got := c.String(); !strings.Contains(got, "curl") || !strings.Contains(got, "443") {
		t.Errorf("String() = %q, want pid/comm/port", got)
	}
	c.Domain = "github.com"
	if got := c.String(); !strings.Contains(got, "github.com") {
		t.Errorf("String() = %q, want domain shown when set", got)
	}
}

func TestProcessAndFileString(t *testing.T) {
	p := Process{PID: 10, PPID: 1, Comm: "sh", Filename: "/bin/sh"}
	if got := p.String(); !strings.Contains(got, "/bin/sh") {
		t.Errorf("Process.String() = %q", got)
	}
	f := FileWrite{PID: 10, Comm: "sh", Path: "/etc/passwd", Op: "open-write"}
	if got := f.String(); !strings.Contains(got, "/etc/passwd") || !strings.Contains(got, "open-write") {
		t.Errorf("FileWrite.String() = %q", got)
	}
}

func TestSessionDuration(t *testing.T) {
	s := &Session{}
	if s.Duration() != 0 {
		t.Errorf("zero FinishedAt should give 0 duration, got %v", s.Duration())
	}
	s.StartedAt = time.Unix(1000, 0)
	s.FinishedAt = time.Unix(1005, 0)
	if s.Duration() != 5*time.Second {
		t.Errorf("Duration() = %v, want 5s", s.Duration())
	}
}
