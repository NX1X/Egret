#!/usr/bin/env bash
# F-C live re-gate: run block mode inside a cgroup-NAMESPACED docker container - the
# topology the bare-host validate-block-mode.sh cannot reach. This exercises the
# post-setup self-probe's fail-open DETECTION (netsec F-C): on a namespaced runner
# the `socket cgroupv2` match may miss, and the self-probe must catch that and refuse
# block mode fail-closed rather than run an unconfined build that thinks it's confined.
#
#   ./scripts/validate-block-mode-container.sh
#
# Needs docker (the host kernel must have BTF - it's bind-mounted read-only). The
# container runs --privileged so egret has CAP_BPF + nftables; it still gets its own
# cgroup namespace, which is exactly the F-C condition.
#
# Outcome classes (all informative - read RESULT):
#   ABORTED via self-probe  -> F-C fail-open DETECTED and refused (fail-closed). GOOD.
#   RUNS + raw IP blocked    -> cgroup match works even namespaced here (confined). GOOD.
#   RUNS + raw IP REACHED    -> BAD: fail-open NOT detected (self-probe hole to fix).
#
# NOTE: first run may need iteration on your host (privileged nft, cgroup delegation
# inside the container, BTF availability all vary). It uses the COMMITTED eBPF
# bindings (go build), so `make generate` is not required inside the container.
set -uo pipefail
cd "$(dirname "$0")/.."
command -v docker >/dev/null || { echo "docker required"; exit 1; }
[ -f /sys/kernel/btf/vmlinux ] || { echo "host kernel has no BTF (/sys/kernel/btf/vmlinux)"; exit 1; }

IMG=egret-regate:local
echo "=== building test image (go + clang + nft) ==="
docker build -q -t "$IMG" - <<'DOCKER' || { echo "image build failed"; exit 1; }
FROM golang:1.25-bookworm
RUN apt-get update && apt-get install -y --no-install-recommends \
      clang llvm libbpf-dev nftables curl ca-certificates \
 && rm -rf /var/lib/apt/lists/*
RUN useradd -u 1000 -m builduser
DOCKER

echo "=== running block mode inside a cgroup-namespaced container ==="
docker run --rm --privileged \
  -v /sys/kernel/btf:/sys/kernel/btf:ro \
  -v "$PWD":/src -w /src \
  -e EGRET_BUILD_UID=1000 -e EGRET_BUILD_GID=1000 \
  "$IMG" bash -uo pipefail -c '
    echo "  cgroup ns: $(readlink /proc/self/ns/cgroup)"
    # eBPF tracepoints need tracefs/debugfs; privileged containers do not mount it by
    # default. Mount it (best-effort) so the collector can attach.
    mount -t tracefs tracefs /sys/kernel/tracing 2>/dev/null \
      || mount -t debugfs debugfs /sys/kernel/debug 2>/dev/null \
      || echo "  (could not mount tracefs/debugfs; collector may fail)"
    go build -buildvcs=false -o bin/egret ./cmd/egret || { echo "build failed"; exit 2; }
    cat > /tmp/pol.yaml <<YAML
version: 1
mode: block
egress: { allowed-endpoints: [example.com], block-raw-ip: true }
report: { format: [json], output-dir: /tmp/rep }
YAML
    out=$(./bin/egret run --mode block --config /tmp/pol.yaml -- \
            bash -c "curl -sS --max-time 6 -o /dev/null https://8.8.8.8 && echo RAW-REACHED || echo raw-blocked" 2>&1)
    echo "----- egret output -----"; echo "$out"; echo "------------------------"
    if echo "$out" | grep -q "self-probe FAILED"; then
      echo "RESULT: ABORTED via self-probe -> F-C fail-open DETECTED + refused (fail-closed). GOOD."
    elif echo "$out" | grep -q "RAW-REACHED"; then
      echo "RESULT: RUNS + raw IP REACHED -> BAD: fail-open NOT detected."
    elif echo "$out" | grep -q "raw-blocked"; then
      echo "RESULT: RUNS + raw IP blocked -> cgroup match works even namespaced (confined)."
    else
      echo "RESULT: inconclusive (egret aborted for another reason - see output)."
    fi
  '
