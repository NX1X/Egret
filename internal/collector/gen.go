package collector

// eBPF code generation. Running `go generate ./...` invokes bpf2go, which
// compiles internal/bpf/*.bpf.c with clang and emits, into THIS package, a Go
// loader plus the embedded object for each of bpfel/bpfeb. The generated files
// (network_bpfel.go, …) are gitignored - regenerate them on a Linux box with
// clang + kernel BTF (see the kernel-vm-test skill). Generation must run here,
// not in internal/bpf, so the unexported loader symbols are local to the
// collector that uses them.
//
// -D__TARGET_ARCH_x86: libbpf's PT_REGS_* / BPF_KPROBE macros need the target CPU
// arch defined, which the arch-neutral -target bpfel/bpfeb does not set. We ship
// linux/amd64; an arm64 build would use -D__TARGET_ARCH_arm64 (a follow-up).
//
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -no-strip -target bpfel,bpfeb network ../bpf/network.bpf.c -- -D__TARGET_ARCH_x86
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -no-strip -target bpfel,bpfeb process ../bpf/process.bpf.c -- -D__TARGET_ARCH_x86
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -no-strip -target bpfel,bpfeb file ../bpf/file.bpf.c -- -D__TARGET_ARCH_x86
