//go:build ignore

// network.bpf.c - observe outbound connections.
//
// Attaches to tcp_v4_connect / tcp_v6_connect (kprobes) and emits one
// conn_event per outbound TCP connection over a ring buffer. UDP (udp_sendmsg)
// is a documented follow-up.
//
// The conn_event layout MUST stay byte-for-byte identical to the Go connEvent
// struct in internal/collector/collector_linux.go.

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";

#define AF_INET 2
#define AF_INET6 10
#define IPPROTO_TCP 6

struct conn_event {
	__u32 pid;
	__u16 dport; // network byte order
	__u8 family; // AF_INET / AF_INET6
	__u8 proto;  // IPPROTO_TCP
	__u8 addr[16]; // v4 in addr[0..3], or full v6
	char comm[16];
};

// Force the type into BTF so bpf2go can generate the Go mirror.
struct conn_event *unused_conn_event __attribute__((unused));

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 24); // 16 MiB
} events SEC(".maps");

// Destination capture reads the caller-supplied sockaddr argument (`uaddr`,
// 2nd arg of tcp_v{4,6}_connect), NOT `sk`. At kprobe *entry* the destination
// fields on `sk` (skc_daddr/skc_dport) are not yet populated, so they come
// back zero; the sockaddr argument is the address the app is connecting to and
// is fully populated on entry. Ports (sin_port/sin6_port) are __be16 - kept in
// network byte order; userspace does ntohs. All reads go through BPF_CORE_READ
// for CO-RE safety.
static __always_inline int submit_tcp4(struct sockaddr_in *sin)
{
	struct conn_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e)
		return 0;

	e->pid = bpf_get_current_pid_tgid() >> 32;
	e->proto = IPPROTO_TCP;
	e->family = AF_INET;
	e->dport = BPF_CORE_READ(sin, sin_port);
	bpf_get_current_comm(&e->comm, sizeof(e->comm));

	__builtin_memset(e->addr, 0, sizeof(e->addr));
	__u32 v4 = BPF_CORE_READ(sin, sin_addr.s_addr);
	__builtin_memcpy(e->addr, &v4, sizeof(v4));

	bpf_ringbuf_submit(e, 0);
	return 0;
}

static __always_inline int submit_tcp6(struct sockaddr_in6 *sin6)
{
	struct conn_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e)
		return 0;

	e->pid = bpf_get_current_pid_tgid() >> 32;
	e->proto = IPPROTO_TCP;
	e->family = AF_INET6;
	e->dport = BPF_CORE_READ(sin6, sin6_port);
	bpf_get_current_comm(&e->comm, sizeof(e->comm));

	__builtin_memset(e->addr, 0, sizeof(e->addr));
	BPF_CORE_READ_INTO(&e->addr, sin6, sin6_addr.in6_u.u6_addr8);

	bpf_ringbuf_submit(e, 0);
	return 0;
}

// tcp_v4_connect(struct sock *sk, struct sockaddr *uaddr, int addr_len)
SEC("kprobe/tcp_v4_connect")
int BPF_KPROBE(trace_tcp_v4_connect, struct sock *sk, struct sockaddr *uaddr)
{
	return submit_tcp4((struct sockaddr_in *)uaddr);
}

// tcp_v6_connect(struct sock *sk, struct sockaddr *uaddr, int addr_len)
SEC("kprobe/tcp_v6_connect")
int BPF_KPROBE(trace_tcp_v6_connect, struct sock *sk, struct sockaddr *uaddr)
{
	return submit_tcp6((struct sockaddr_in6 *)uaddr);
}
