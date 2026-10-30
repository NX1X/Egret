//go:build ignore

// process.bpf.c - observe process execution.
//
// Attaches to the sched_process_exec raw tracepoint and emits one
// egret_proc_event per successful exec. The egret_proc_event layout MUST match the Go procEvent struct in
// internal/collector/collector_linux.go.

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include "scope.h"

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

// sched_process_exec fires once per SUCCESSFUL exec, after the new program is
// in place, on whatever CPU the task runs. It is attached as a raw tracepoint
// (BPF_RAW_TRACEPOINT_OPEN), not through a perf event.
//
// Why not the sys_enter_execve tracepoint used before: cilium attaches syscall
// tracepoints through a perf event opened on CPU 0, and on newer kernels
// (verified on 7.0, GitHub's ubuntu-latest) the program then ran only for tasks
// on CPU 0, so most execs were never recorded and nothing counted the loss.
//
// Raw tracepoint args: (struct task_struct *p, pid_t old_pid,
// struct linux_binprm *bprm). comm is already the new program's name here.
SEC("raw_tracepoint/sched_process_exec")
int trace_exec(struct bpf_raw_tracepoint_args *ctx)
{
	if (!in_scope())
		return 0;

	struct egret_proc_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e) {
		count_drop();
		return 0;
	}

	struct task_struct *task = (struct task_struct *)bpf_get_current_task();
	struct linux_binprm *bprm = (struct linux_binprm *)ctx->args[2];

	e->pid = bpf_get_current_pid_tgid() >> 32;
	e->ppid = BPF_CORE_READ(task, real_parent, tgid);
	bpf_get_current_comm(&e->comm, sizeof(e->comm));

	const char *filename = BPF_CORE_READ(bprm, filename);
	bpf_probe_read_kernel_str(&e->filename, sizeof(e->filename), filename);

	bpf_ringbuf_submit(e, 0);
	return 0;
}
