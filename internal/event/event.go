// Package event defines the platform-neutral data types that flow from the
// eBPF collector through the policy engine into the report writers.
//
// The kernel-side eBPF programs (internal/bpf/*.bpf.c) emit C structs over a
// ring buffer; the Linux collector decodes them into the *Event types here.
// These types carry no Linux-only dependencies so the policy, report, and
// audit packages build and test on any platform.
package event

import (
	"fmt"
	"net"
	"time"
)

// Kind classifies an event for reporting and policy evaluation.
type Kind string

const (
	KindConnection Kind = "connection"
	KindProcess    Kind = "process"
	KindFile       Kind = "file"
)

// Connection is an observed outbound network connection (one tcp_connect or
// UDP sendto). Domain is filled in later by correlating Daddr against the DNS
// proxy's domain→IP map; it is empty for raw-IP connections.
type Connection struct {
	Time   time.Time `json:"time"`
	PID    uint32    `json:"pid"`
	Comm   string    `json:"comm"`
	Daddr  net.IP    `json:"daddr"`
	Dport  uint16    `json:"dport"`
	Proto  string    `json:"proto"` // "tcp" | "udp"
	Domain string    `json:"domain,omitempty"`
}

func (c Connection) String() string {
	dst := c.Daddr.String()
	if c.Domain != "" {
		dst = fmt.Sprintf("%s (%s)", c.Domain, c.Daddr)
	}
	return fmt.Sprintf("%-6d %-16s %s:%d/%s", c.PID, c.Comm, dst, c.Dport, c.Proto)
}

// Process is an observed exec/fork in the monitored tree.
type Process struct {
	Time     time.Time `json:"time"`
	PID      uint32    `json:"pid"`
	PPID     uint32    `json:"ppid"`
	Comm     string    `json:"comm"`
	Filename string    `json:"filename"`
}

func (p Process) String() string {
	return fmt.Sprintf("%-6d (ppid %-6d) %s %s", p.PID, p.PPID, p.Comm, p.Filename)
}

// FileWrite is an observed write/create/rename targeting a path.
type FileWrite struct {
	Time time.Time `json:"time"`
	PID  uint32    `json:"pid"`
	Comm string    `json:"comm"`
	Path string    `json:"path"`
	Op   string    `json:"op"` // "open-write" | "rename" | ...
}

func (f FileWrite) String() string {
	return fmt.Sprintf("%-6d %-16s %s %s", f.PID, f.Comm, f.Op, f.Path)
}

// Violation is a policy decision flagging an event. In audit mode it is logged
// only; in block mode a network Violation corresponds to a dropped connection.
type Violation struct {
	Kind    Kind   `json:"kind"`
	Reason  string `json:"reason"`
	Detail  string `json:"detail"`
	Blocked bool   `json:"blocked"` // true if enforcement actually dropped it
}

// Session is the full record of one `egret run`, accumulated by the collector
// and consumed by the report and audit packages.
type Session struct {
	StartedAt   time.Time    `json:"started_at"`
	FinishedAt  time.Time    `json:"finished_at"`
	Command     []string     `json:"command"`
	Mode        string       `json:"mode"` // "audit" | "block"
	ExitCode    int          `json:"exit_code"`
	Connections []Connection `json:"connections"`
	Processes   []Process    `json:"processes"`
	FileWrites  []FileWrite  `json:"file_writes"`
	Violations  []Violation  `json:"violations"`
}

// Duration returns how long the monitored command ran.
func (s *Session) Duration() time.Duration {
	if s.FinishedAt.IsZero() {
		return 0
	}
	return s.FinishedAt.Sub(s.StartedAt)
}
