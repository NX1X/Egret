// scope.h - shared by every Egret probe.
//
// Scope: Egret records only the monitored build. The build runs in its own
// cgroup-v2 (created by the enforcer in audit and block mode), and userspace
// writes that cgroup's id into scope_cgroup before the build starts. An event
// whose task is in another cgroup (the runner's own agents, other jobs on the
// host) is not recorded. 0 means "no scope": record everything, used only when
// no build cgroup could be created.
//
// The match is exact (bpf_get_current_cgroup_id). A block-mode build runs
// without privilege and cannot create child cgroups or move itself; an
// audit-mode build runs as root and is not a boundary anyway.
//
// Drops: when the ring buffer is full, bpf_ringbuf_reserve fails and the event
// is lost. Each loss is counted in `dropped`, which userspace reports, so a
// blind spot is never silent.

#ifndef EGRET_SCOPE_H
#define EGRET_SCOPE_H

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64);
} scope_cgroup SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64);
} dropped SEC(".maps");

static __always_inline int in_scope(void)
{
	__u32 key = 0;
	__u64 *want = bpf_map_lookup_elem(&scope_cgroup, &key);
	if (!want || *want == 0)
		return 1;
	return bpf_get_current_cgroup_id() == *want;
}

static __always_inline void count_drop(void)
{
	__u32 key = 0;
	__u64 *n = bpf_map_lookup_elem(&dropped, &key);
	if (n)
		*n += 1; // per-CPU slot: no other CPU writes it
}

#endif
