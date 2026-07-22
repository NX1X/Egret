//go:build ignore

// file.bpf.c - observe writes to the filesystem.
//
// Attaches to the sys_enter_openat tracepoint and emits a file_event only when
// the open carries write intent (O_WRONLY | O_RDWR | O_CREAT | O_TRUNC). The
// userspace policy engine decides whether the path is protected. The
// file_event layout MUST match the Go fileEvent struct in
// internal/collector/collector_linux.go.

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

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

SEC("tracepoint/syscalls/sys_enter_openat")
int trace_openat(struct trace_event_raw_sys_enter *ctx)
{
	// args[2] is `flags` for openat(dfd, filename, flags, mode).
	long flags = (long)ctx->args[2];
	if (!(flags & WRITE_INTENT))
		return 0;

	struct file_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e)
		return 0;

	e->pid = bpf_get_current_pid_tgid() >> 32;
	bpf_get_current_comm(&e->comm, sizeof(e->comm));

	const char *filename = (const char *)ctx->args[1];
	bpf_probe_read_user_str(&e->filename, sizeof(e->filename), filename);

	bpf_ringbuf_submit(e, 0);
	return 0;
}
