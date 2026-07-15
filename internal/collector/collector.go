// Package collector loads Egret's eBPF programs, attaches them to kernel
// hooks, and decodes ring-buffer events into the platform-neutral types in
// internal/event.
//
// The real implementation is Linux-only (collector_linux.go). On other
// platforms only the interface and an unsupported stub are compiled, so the
// rest of the codebase still builds.
package collector

import (
	"errors"

	"github.com/NX1X/Egret/internal/event"
)

// ErrUnsupported is returned by New on non-Linux platforms.
var ErrUnsupported = errors.New("eBPF collector requires Linux")

// Collector streams observed kernel events on typed channels until Close is
// called or its context is cancelled, at which point the channels are drained
// and closed.
type Collector interface {
	// Connections yields outbound network connections.
	Connections() <-chan event.Connection
	// Processes yields exec events in the monitored tree.
	Processes() <-chan event.Process
	// FileWrites yields write-intent file opens.
	FileWrites() <-chan event.FileWrite
	// Close detaches all probes and releases kernel resources. Safe to call
	// once; idempotency is the implementation's responsibility.
	Close() error
}
