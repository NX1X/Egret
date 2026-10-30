//go:build linux

package collector

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/NX1X/Egret/internal/event"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

const (
	afInet  = 2
	afInet6 = 10
)

// Raw wire structs - these MUST match the C structs in internal/bpf byte for
// byte. bpf programs are compiled little-endian (bpfel) on the common arches;
// integer fields are read host-endian, except dport which is network order.
type connEventRaw struct {
	PID    uint32
	Dport  uint16
	Family uint8
	Proto  uint8
	Addr   [16]byte
	Comm   [16]byte
}

type procEventRaw struct {
	PID      uint32
	PPID     uint32
	Comm     [16]byte
	Filename [256]byte
}

type fileEventRaw struct {
	PID      uint32
	Comm     [16]byte
	Filename [256]byte
}

// LinuxCollector holds all attached probes, ring-buffer readers, and the
// goroutines draining them into typed channels.
type LinuxCollector struct {
	net  networkObjects
	proc processObjects
	file fileObjects

	links   []link.Link
	readers []*ringbuf.Reader

	conns  chan event.Connection
	procs  chan event.Process
	writes chan event.FileWrite

	done      chan struct{}  // closed by Close to stop the ctx watcher
	readersWG sync.WaitGroup // the three ring readers
	watchWG   sync.WaitGroup // the ctx watcher
	closeOnce sync.Once

	userLost atomic.Uint64 // records read from a ring but not decodable
	notes    []string      // coverage notes from attach (see Notes)

	closed       bool   // set by Close; the maps are gone after it
	finalDropped uint64 // drop count read by Close before it unloads the maps
	finalErr     error  // why the kernel drop count could not be read
}

// New loads the eBPF objects, attaches every probe, and starts the reader
// goroutines. The returned collector streams until ctx is cancelled (or Close).
//
// scopeCgroup is the cgroup-v2 id of the build: the probes record only tasks
// in that cgroup. 0 records every task on the host (no build cgroup exists).
// The scope is written before any probe attaches, so no out-of-scope event is
// ever recorded.
func New(ctx context.Context, scopeCgroup uint64) (Collector, error) {
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("removing memlock rlimit: %w", err)
	}

	c := &LinuxCollector{
		conns:  make(chan event.Connection, 1024),
		procs:  make(chan event.Process, 1024),
		writes: make(chan event.FileWrite, 1024),
		done:   make(chan struct{}),
	}

	if err := loadNetworkObjects(&c.net, nil); err != nil {
		return nil, fmt.Errorf("loading network objects: %w", verboseVerifier(err))
	}
	if err := loadProcessObjects(&c.proc, nil); err != nil {
		c.closeKernel()
		return nil, fmt.Errorf("loading process objects: %w", verboseVerifier(err))
	}
	if err := loadFileObjects(&c.file, nil); err != nil {
		c.closeKernel()
		return nil, fmt.Errorf("loading file objects: %w", verboseVerifier(err))
	}

	if err := c.setScope(scopeCgroup); err != nil {
		c.closeKernel()
		return nil, err
	}
	if err := c.attach(); err != nil {
		c.closeKernel()
		return nil, err
	}
	if err := c.startReaders(ctx); err != nil {
		c.closeKernel()
		return nil, err
	}
	return c, nil
}

// SetScope changes the probes' scope while they run. 0 widens them to the
// whole host (used when the build had to start outside its cgroup).
func (c *LinuxCollector) SetScope(id uint64) error { return c.setScope(id) }

// setScope writes the build's cgroup id into every probe's scope map.
func (c *LinuxCollector) setScope(id uint64) error {
	for name, m := range c.scopeMaps() {
		if err := m.Put(uint32(0), id); err != nil {
			return fmt.Errorf("setting the %s probe scope: %w", name, err)
		}
	}
	return nil
}

func (c *LinuxCollector) scopeMaps() map[string]*ebpf.Map {
	return map[string]*ebpf.Map{"network": c.net.ScopeCgroup, "process": c.proc.ScopeCgroup, "file": c.file.ScopeCgroup}
}

// Dropped returns how many events were lost: the per-CPU drop counters of
// every probe (full rings) plus records userspace could not decode. The error
// is non-nil when a kernel counter could not be read, so the count may be low;
// the caller must report that instead of treating it as "nothing lost".
func (c *LinuxCollector) Dropped() (uint64, error) {
	if c.closed {
		return c.finalDropped, c.finalErr
	}
	total := c.userLost.Load()
	var firstErr error
	for name, m := range map[string]*ebpf.Map{"network": c.net.Dropped, "process": c.proc.Dropped, "file": c.file.Dropped} {
		var perCPU []uint64
		if m == nil {
			firstErr = fmt.Errorf("the %s drop counter is not loaded", name)
			continue
		}
		if err := m.Lookup(uint32(0), &perCPU); err != nil {
			if firstErr == nil {
				firstErr = fmt.Errorf("reading the %s drop counter: %w", name, err)
			}
			continue
		}
		for _, n := range perCPU {
			total += n
		}
	}
	return total, firstErr
}

func (c *LinuxCollector) attach() error {
	// Kprobes run on every CPU: the network connect probes and the file probe.
	for _, p := range []struct {
		sym  string
		prog *ebpf.Program
	}{
		{"tcp_v4_connect", c.net.TraceTcpV4Connect},
		{"tcp_v6_connect", c.net.TraceTcpV6Connect},
	} {
		l, err := link.Kprobe(p.sym, p.prog, nil)
		if err != nil {
			return fmt.Errorf("attaching kprobe %s: %w", p.sym, err)
		}
		c.links = append(c.links, l)
	}

	// Exec: a raw tracepoint, attached without a perf event, so it runs on
	// every CPU. (A syscall tracepoint attached by cilium through a perf event
	// on CPU 0 ran only for tasks on CPU 0 on newer kernels.)
	l, err := link.AttachRawTracepoint(link.RawTracepointOptions{Name: "sched_process_exec", Program: c.proc.TraceExec})
	if err != nil {
		return fmt.Errorf("attaching raw tracepoint sched_process_exec: %w", err)
	}
	c.links = append(c.links, l)

	// File writes: do_sys_openat2 when it can be probed (it can be inlined on
	// some builds), else the openat syscall tracepoint, with a report note.
	if l, err := link.Kprobe("do_sys_openat2", c.file.TraceOpenat2, nil); err == nil {
		c.links = append(c.links, l)
	} else {
		l, terr := link.Tracepoint("syscalls", "sys_enter_openat", c.file.TraceOpenat, nil)
		if terr != nil {
			return fmt.Errorf("attaching the file probe: kprobe do_sys_openat2: %v; tracepoint sys_enter_openat: %w", err, terr)
		}
		c.links = append(c.links, l)
		c.notes = append(c.notes, "File writes are watched through the openat syscall tracepoint, because do_sys_openat2 could not be probed on this kernel. On some kernels that tracepoint misses events, so file coverage may be incomplete.")
	}
	return nil
}

// Notes are coverage facts about how the probes were attached, for the report.
func (c *LinuxCollector) Notes() []string { return c.notes }

func (c *LinuxCollector) startReaders(ctx context.Context) error {
	netRd, err := ringbuf.NewReader(c.net.Events)
	if err != nil {
		return fmt.Errorf("opening network ringbuf: %w", err)
	}
	procRd, err := ringbuf.NewReader(c.proc.Events)
	if err != nil {
		netRd.Close()
		return fmt.Errorf("opening process ringbuf: %w", err)
	}
	fileRd, err := ringbuf.NewReader(c.file.Events)
	if err != nil {
		netRd.Close()
		procRd.Close()
		return fmt.Errorf("opening file ringbuf: %w", err)
	}
	c.readers = []*ringbuf.Reader{netRd, procRd, fileRd}

	// Cancellation: when ctx is done (or Close was called), close the readers,
	// which unblocks the Read loops below. Selecting on c.done as well means
	// Close() never deadlocks waiting on a context that was never cancelled.
	c.watchWG.Add(1)
	go func() {
		defer c.watchWG.Done()
		select {
		case <-ctx.Done():
		case <-c.done:
		}
		for _, r := range c.readers {
			_ = r.Close()
		}
	}()

	c.readersWG.Add(3)
	go c.readConns(netRd)
	go c.readProcs(procRd)
	go c.readFiles(fileRd)
	return nil
}

func (c *LinuxCollector) readConns(r *ringbuf.Reader) {
	defer c.readersWG.Done()
	defer close(c.conns)
	for {
		rec, err := r.Read()
		if err != nil {
			if ringDone(err) {
				return
			}
			continue
		}
		var raw connEventRaw
		if err := binary.Read(bytes.NewReader(rec.RawSample), binary.LittleEndian, &raw); err != nil {
			c.userLost.Add(1)
			continue
		}
		c.conns <- event.Connection{
			Time:  time.Now(),
			PID:   raw.PID,
			Comm:  goString(raw.Comm[:]),
			Daddr: decodeAddr(raw.Family, raw.Addr),
			Dport: ntohs(raw.Dport),
			Proto: "tcp",
		}
	}
}

func (c *LinuxCollector) readProcs(r *ringbuf.Reader) {
	defer c.readersWG.Done()
	defer close(c.procs)
	for {
		rec, err := r.Read()
		if err != nil {
			if ringDone(err) {
				return
			}
			continue
		}
		var raw procEventRaw
		if err := binary.Read(bytes.NewReader(rec.RawSample), binary.LittleEndian, &raw); err != nil {
			c.userLost.Add(1)
			continue
		}
		c.procs <- event.Process{
			Time:     time.Now(),
			PID:      raw.PID,
			PPID:     raw.PPID,
			Comm:     goString(raw.Comm[:]),
			Filename: goString(raw.Filename[:]),
		}
	}
}

func (c *LinuxCollector) readFiles(r *ringbuf.Reader) {
	defer c.readersWG.Done()
	defer close(c.writes)
	for {
		rec, err := r.Read()
		if err != nil {
			if ringDone(err) {
				return
			}
			continue
		}
		var raw fileEventRaw
		if err := binary.Read(bytes.NewReader(rec.RawSample), binary.LittleEndian, &raw); err != nil {
			c.userLost.Add(1)
			continue
		}
		c.writes <- event.FileWrite{
			Time: time.Now(),
			PID:  raw.PID,
			Comm: goString(raw.Comm[:]),
			Path: goString(raw.Filename[:]),
			Op:   "open-write",
		}
	}
}

func (c *LinuxCollector) Connections() <-chan event.Connection { return c.conns }
func (c *LinuxCollector) Processes() <-chan event.Process      { return c.procs }
func (c *LinuxCollector) FileWrites() <-chan event.FileWrite   { return c.writes }

// ringDone reports whether a ring Read error means "no more records": the
// reader was flushed (Close drained it) or closed (ctx cancelled).
func ringDone(err error) bool {
	return errors.Is(err, ringbuf.ErrFlushed) || errors.Is(err, ringbuf.ErrClosed)
}

// Close detaches the probes, drains every ring, then unloads the objects.
//
// Order matters. Detaching first means no new event arrives. Flush then makes
// each reader return every record still in its ring before it stops, so an
// event the build produced just before it exited is never lost. (Closing the
// readers straight away discarded those records, and because the ring was not
// full, the drop counter did not count them.) On ctx cancellation the watcher
// closes the readers instead, which is the abort path.
func (c *LinuxCollector) Close() error {
	c.closeOnce.Do(func() {
		for _, l := range c.links {
			_ = l.Close()
		}
		c.links = nil
		for _, r := range c.readers {
			_ = r.Flush()
		}
		c.readersWG.Wait()
		close(c.done)
		c.watchWG.Wait()
		for _, r := range c.readers {
			_ = r.Close()
		}
		c.finalDropped, c.finalErr = c.Dropped()
		c.closed = true
		c.closeKernel()
	})
	return nil
}

func (c *LinuxCollector) closeKernel() {
	for _, l := range c.links {
		_ = l.Close()
	}
	c.net.Close()
	c.proc.Close()
	c.file.Close()
}

// --- helpers ---

func decodeAddr(family uint8, addr [16]byte) net.IP {
	switch family {
	case afInet:
		return net.IPv4(addr[0], addr[1], addr[2], addr[3])
	case afInet6:
		ip := make(net.IP, 16)
		copy(ip, addr[:])
		return ip
	default:
		return nil
	}
}

func ntohs(v uint16) uint16 { return v<<8 | v>>8 }

// verboseVerifier expands an eBPF *VerifierError so the full kernel log is
// printed (it is truncated by default). Invaluable when a probe is rejected.
func verboseVerifier(err error) error {
	var ve *ebpf.VerifierError
	if errors.As(err, &ve) {
		return fmt.Errorf("%+v", ve)
	}
	return err
}

func goString(b []byte) string {
	if i := bytes.IndexByte(b, 0); i >= 0 {
		b = b[:i]
	}
	return string(b)
}
