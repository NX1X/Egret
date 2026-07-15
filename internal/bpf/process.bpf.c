//go:build ignore

// process.bpf.c — observe process execution.
//
// Attaches to the sys_enter_execve tracepoint and emits one egret_proc_event per
// exec. The egret_proc_event layout MUST match the Go procEvent struct in
// internal/collector/collector_linux.go.

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "GPL";

#define FILENAME_LEN 256

struct egret_proc_event {
	__u32 pid;
	__u32 ppid;
	char comm[16];
	char filename[FILENAME_LEN];
};

struct egret_proc_event *unused_egret_proc_event __attribute__((unused));

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 24);
} events SEC(".maps");

// Layout of the sys_enter_execve tracepoint args. CO-RE reads tolerate kernel
// differences; the filename pointer is the first syscall argument.
SEC("tracepoint/syscalls/sys_enter_execve")
int trace_execve(struct trace_event_raw_sys_enter *ctx)
{
	struct egret_proc_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e)
		return 0;

	struct task_struct *task = (struct task_struct *)bpf_get_current_task();

	e->pid = bpf_get_current_pid_tgid() >> 32;
	e->ppid = BPF_CORE_READ(task, real_parent, tgid);
	bpf_get_current_comm(&e->comm, sizeof(e->comm));

	const char *filename = (const char *)ctx->args[0];
	bpf_probe_read_user_str(&e->filename, sizeof(e->filename), filename);

	bpf_ringbuf_submit(e, 0);
	return 0;
}
