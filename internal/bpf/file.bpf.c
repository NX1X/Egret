//go:build ignore

// file.bpf.c - observe writes to the filesystem.
//
// Attaches to do_sys_openat2 (kprobe) and emits a file_event only when the
// open carries write intent (O_WRONLY | O_RDWR | O_CREAT | O_TRUNC). The
// userspace policy engine decides whether the path is protected. The
// file_event layout MUST match the Go fileEvent struct in
// internal/collector/collector_linux.go.

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include "scope.h"

char LICENSE[] SEC("license") = "GPL";

#define FILENAME_LEN 256

// open(2) flags (stable ABI values).
#define O_WRONLY 00000001
#define O_RDWR 00000002
#define O_CREAT 00000100
#define O_TRUNC 00001000
#define WRITE_INTENT (O_WRONLY | O_RDWR | O_CREAT | O_TRUNC)

struct file_event {
	__u32 pid;
	char comm[16];
	char filename[FILENAME_LEN];
};

struct file_event *unused_file_event __attribute__((unused));

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 24);
} events SEC(".maps");

// emit_write records one write-intent open. filename is a user pointer.
static __always_inline int emit_write(const char *filename)
{
	if (!in_scope())
		return 0;

	struct file_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e) {
		count_drop();
		return 0;
	}

	e->pid = bpf_get_current_pid_tgid() >> 32;
	bpf_get_current_comm(&e->comm, sizeof(e->comm));
	bpf_probe_read_user_str(&e->filename, sizeof(e->filename), filename);

	bpf_ringbuf_submit(e, 0);
	return 0;
}

// Primary hook: do_sys_openat2, which open(2), creat(2), openat(2) and
// openat2(2) all reach. A kprobe runs on every CPU. (The sys_enter_openat
// tracepoint below ran only on CPU 0 on newer kernels; see process.bpf.c.)
// do_sys_openat2(int dfd, const char __user *filename, struct open_how *how)
SEC("kprobe/do_sys_openat2")
int BPF_KPROBE(trace_openat2, int dfd, const char *filename, struct open_how *how)
{
	__u64 flags = BPF_CORE_READ(how, flags);
	if (!(flags & WRITE_INTENT))
		return 0;
	return emit_write(filename);
}

// Fallback, attached only when do_sys_openat2 cannot be probed on this kernel.
// The report then says file coverage may be incomplete.
SEC("tracepoint/syscalls/sys_enter_openat")
int trace_openat(struct trace_event_raw_sys_enter *ctx)
{
	// args[2] is `flags` for openat(dfd, filename, flags, mode).
	long flags = (long)ctx->args[2];
	if (!(flags & WRITE_INTENT))
		return 0;
	return emit_write((const char *)ctx->args[1]);
}
