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

// Raw wire structs — these MUST match the C structs in internal/bpf byte for
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

	done      chan struct{} // closed by Close to unblock the ctx watcher
	wg        sync.WaitGroup
	closeOnce sync.Once
}

// New loads the eBPF objects, attaches every probe, and starts the reader
// goroutines. The returned collector streams until ctx is cancelled (or Close).
func New(ctx context.Context) (Collector, error) {
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

func (c *LinuxCollector) attach() error {
	// Kprobes: program fields are *ebpf.Program from the generated objects.
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
	// Tracepoints.
	for _, t := range []struct {
		group, name string
		prog        *ebpf.Program
	}{
		{"syscalls", "sys_enter_execve", c.proc.TraceExecve},
		{"syscalls", "sys_enter_openat", c.file.TraceOpenat},
	} {
		l, err := link.Tracepoint(t.group, t.name, t.prog, nil)
		if err != nil {
			return fmt.Errorf("attaching tracepoint %s/%s: %w", t.group, t.name, err)
		}
		c.links = append(c.links, l)
	}
	return nil
}

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
	c.wg.Add(1)
	go func() {
		defer c.wg.Done()
		select {
		case <-ctx.Done():
		case <-c.done:
		}
		for _, r := range c.readers {
			_ = r.Close()
		}
	}()

	c.wg.Add(3)
	go c.readConns(netRd)
	go c.readProcs(procRd)
	go c.readFiles(fileRd)
	return nil
}

func (c *LinuxCollector) readConns(r *ringbuf.Reader) {
	defer c.wg.Done()
	defer close(c.conns)
	for {
		rec, err := r.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return
			}
			continue
		}
		var raw connEventRaw
		if err := binary.Read(bytes.NewReader(rec.RawSample), binary.LittleEndian, &raw); err != nil {
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
	defer c.wg.Done()
	defer close(c.procs)
	for {
		rec, err := r.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return
			}
			continue
		}
		var raw procEventRaw
		if err := binary.Read(bytes.NewReader(rec.RawSample), binary.LittleEndian, &raw); err != nil {
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
	defer c.wg.Done()
	defer close(c.writes)
	for {
		rec, err := r.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return
			}
			continue
		}
		var raw fileEventRaw
		if err := binary.Read(bytes.NewReader(rec.RawSample), binary.LittleEndian, &raw); err != nil {
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

// Close detaches probes and unloads objects. The reader goroutines exit when
// their readers close (driven by ctx cancellation or here).
func (c *LinuxCollector) Close() error {
	c.closeOnce.Do(func() {
		close(c.done) // unblock the ctx watcher if ctx was never cancelled
		for _, r := range c.readers {
			_ = r.Close()
		}
		c.wg.Wait()
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
