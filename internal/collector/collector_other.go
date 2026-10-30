//go:build !linux

package collector

import "context"

// New is unavailable off Linux; the CLI's executeRun stub blocks before this is
// ever reached, but the symbol must exist for the package to compile.
func New(_ context.Context, _ uint64) (Collector, error) {
	return nil, ErrUnsupported
}
