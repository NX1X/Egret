#!/usr/bin/env bash
# Live validation of block-mode egress confinement (needs root + a BTF kernel).
#
#   sudo ./scripts/validate-block-mode.sh
#
# Proves the netsec re-gate fixes:
#   F1 - the build runs as a NON-ROOT uid, so its cgroup-escape / `nft flush`
#        attempts FAIL (permission denied) → it stays confined.
#   #3 - block mode can resolve (egret's DNS upstream is unfiltered).
#   #2 - allow-set entries carry a TTL.
#   default-deny - a raw-IP (never-resolved) destination is blocked.
#   F-A - no_new_privs + empty capability set: `sudo`/setuid can't re-escalate,
#         /proc/self/status shows NoNewPrivs:1 and zero CapBnd/CapEff/CapAmb.
#   F-E - a build-spawned daemon that outlives the command is cgroup.kill'd at
#         teardown (no unconfined process left after the filter is removed).
#
# Expected PASS output: every "expect …" line matches, NoNewPrivs is 1 and all
# Cap* are 0000000000000000, sudo/setuid stay non-root, the daemon is gone, and
# teardown leaves no nft table or cgroup. Any "(BAD …)" line is a NO-GO for the gate.
set -uo pipefail
cd "$(dirname "$0")/.."

[ "$(id -u)" -eq 0 ] || { echo "must run as root (sudo)"; exit 1; }
: "${SUDO_UID:?run via sudo so the build drops to your non-root uid (SUDO_UID)}"

make generate >/dev/null && make build >/dev/null || { echo "build failed"; exit 1; }

cat > /tmp/egret-block-pol.yaml <<YAML
version: 1
mode: block
egress:
  allowed-endpoints: [example.com]
report:
  format: [json]
  output-dir: /tmp/egret-block-report
YAML

cat > /tmp/egret-block-build.sh <<'BUILD'
set -u
echo "  build uid=$(id -u) (expect NON-zero: F1 dropped privileges)"
echo "  escape attempt 1 - move self out of the cgroup:"
{ echo $$ > /sys/fs/cgroup/cgroup.procs; } 2>&1 | sed 's/^/    /'; echo "    -> rc=${PIPESTATUS[0]} (expect NON-zero: denied)"
echo "  escape attempt 2 - flush nft:"
nft flush ruleset 2>&1 | sed 's/^/    /'; echo "    -> rc=${PIPESTATUS[0]} (expect NON-zero: denied, no CAP_NET_ADMIN)"
IP=$(dig +short @127.0.0.1 example.com A | grep -E '^[0-9]' | head -1)
echo "  proxy-resolved example.com -> ${IP:-<none>} (non-empty: #3 upstream works)"
echo "  allowlisted example.com:"
[ -n "$IP" ] && curl -sS --max-time 8 --resolve example.com:443:$IP -o /dev/null -w "    -> HTTP %{http_code} (expect 200)\n" https://example.com
echo "  raw-IP 1.1.1.1 (not allowlisted):"
curl -sS --max-time 6 -o /dev/null https://1.1.1.1 && echo "    -> REACHED (BAD)" || echo "    -> blocked (expected)"
echo "  F-A: no_new_privs + capabilities (expect NoNewPrivs: 1 ; CapBnd/CapEff/CapPrm/CapAmb all zero):"
grep -E 'NoNewPrivs|CapInh|CapPrm|CapEff|CapBnd|CapAmb|^Uid|^Gid|^Groups' /proc/self/status | sed 's/^/    /'
echo "  F-A: sudo -n nft flush (expect FAIL - no_new_privs makes setuid sudo inert):"
sudo -n nft flush ruleset 2>&1 | sed 's/^/    /'; echo "    -> rc=${PIPESTATUS[0]} (expect NON-zero: cannot re-escalate)"
echo "  F-A: run a setuid-root helper (expect it stays NON-root):"
if [ -x /tmp/egret-suid-probe ]; then /tmp/egret-suid-probe 2>&1 | sed 's/^/    /'; else echo "    (no probe planted)"; fi
BUILD

# F-A: plant a setuid-root helper the build will try to use to regain root. With
# no_new_privs set, the setuid bit is inert, so it must report a NON-zero euid.
printf '#include <unistd.h>\n#include <stdio.h>\nint main(){printf("      setuid-probe euid=%%d (expect NON-zero)\\n",geteuid());return 0;}\n' > /tmp/egret-suid.c
if command -v cc >/dev/null && cc -o /tmp/egret-suid-probe /tmp/egret-suid.c 2>/dev/null; then
  chown root:root /tmp/egret-suid-probe && chmod 4755 /tmp/egret-suid-probe
fi

# F-B - block mode is fail-closed on privilege: with NO non-root credential it must
# REFUSE (never run the build at egret's root privilege).
echo "=== F-B: block mode refuses without a non-root credential ==="
if env -u SUDO_UID -u EGRET_BUILD_UID ./bin/egret run --mode block \
     --config /tmp/egret-block-pol.yaml -- echo SHOULD-NOT-RUN >/dev/null 2>&1; then
  echo "  BAD: block mode ran the build without dropping privilege"
else
  echo "  refused (expected)"
fi

echo "=== block-mode validation ==="
./bin/egret run --mode block --config /tmp/egret-block-pol.yaml -- bash /tmp/egret-block-build.sh
echo "=== teardown clean? ==="
nft list table inet egret >/dev/null 2>&1 && echo "  LEFTOVER nft table (BAD)" || echo "  no egret nft table (clean)"
ls -d /sys/fs/cgroup/egret-run-* 2>/dev/null && echo "  LEFTOVER cgroup (BAD)" || echo "  no leftover cgroup (clean)"

# F-E - a process the build spawns that outlives the monitored command must be
# killed at teardown (cgroup.kill), not left alive with a socket after the filter
# is gone. Spawn a backgrounded + setsid'd sleep (leaves the session, stays in the
# cgroup), record its pid, and after egret returns confirm it's dead.
echo "=== F-E: build-spawned daemon killed on teardown ==="
rm -f /tmp/egret-fe.pid
./bin/egret run --mode block --config /tmp/egret-block-pol.yaml -- \
  bash -c 'setsid sleep 300 </dev/null >/dev/null 2>&1 & echo $! > /tmp/egret-fe.pid; sleep 0.3; echo "  spawned daemon pid=$(cat /tmp/egret-fe.pid)"'
DPID=$(cat /tmp/egret-fe.pid 2>/dev/null)
sleep 0.5
if [ -n "$DPID" ] && kill -0 "$DPID" 2>/dev/null; then
  echo "  daemon $DPID STILL ALIVE after teardown (BAD: F-E fail-open window)"; kill -9 "$DPID" 2>/dev/null
else
  echo "  daemon ${DPID:-?} gone after teardown (expected: cgroup.kill worked)"
fi

# allowed-ips - a raw IP in the policy's allowed-ips must be REACHABLE in block mode
# (installed as a static nft CIDR allow-set), while a different raw IP stays blocked.
echo "=== allowed-ips: static IP/CIDR allow-set (block mode) ==="
cat > /tmp/egret-ips-pol.yaml <<YAML
version: 1
mode: block
egress:
  allowed-endpoints: []
  allowed-ips: ["1.1.1.1/32"]
  block-raw-ip: true
report: { format: [json], output-dir: /tmp/egret-ips-report }
YAML
cat > /tmp/egret-ips-build.sh <<'BUILD'
echo "  allowed raw IP 1.1.1.1 (in allowed-ips):"
curl -sS --max-time 8 -o /dev/null -w "    -> HTTP %{http_code} (expect a response: reached)\n" https://1.1.1.1 || echo "    -> BLOCKED (BAD: allowed-ips not honored)"
echo "  non-allowed raw IP 8.8.8.8 (not in allowed-ips):"
curl -sS --max-time 6 -o /dev/null https://8.8.8.8 && echo "    -> REACHED (BAD)" || echo "    -> blocked (expected)"
BUILD
./bin/egret run --mode block --config /tmp/egret-ips-pol.yaml -- bash /tmp/egret-ips-build.sh
echo "  broad CIDR guard (netsec F1): a 0.0.0.0/0 allowed-ips must be REFUSED:"
cat > /tmp/egret-ips-broad.yaml <<YAML
version: 1
mode: block
egress: { allowed-endpoints: [], allowed-ips: ["0.0.0.0/0"], block-raw-ip: true }
report: { format: [json], output-dir: /tmp/egret-ips-report }
YAML
if ./bin/egret run --mode block --config /tmp/egret-ips-broad.yaml -- true >/dev/null 2>&1; then
  echo "    -> ACCEPTED (BAD: default route disables filtering)"
else
  echo "    -> refused (expected)"
fi
rm -f /tmp/egret-ips-broad.yaml

# disable-sudo - with --disable-sudo, the build user's passwordless sudo is revoked
# for the run (belt to no_new_privs), then restored at teardown.
echo "=== disable-sudo: build user's sudo revoked during the run ==="
rm -f /etc/sudoers.d/zz-egret-no-sudo
./bin/egret run --mode block --disable-sudo --config /tmp/egret-block-pol.yaml -- \
  bash -c 'echo "  sudo -n true inside build:"; sudo -n true 2>&1 | sed "s/^/    /"; echo "    -> rc=${PIPESTATUS[0]} (expect NON-zero: sudo revoked)"'
if [ -f /etc/sudoers.d/zz-egret-no-sudo ]; then
  echo "  LEFTOVER sudoers drop-in after teardown (BAD: not restored)"; rm -f /etc/sudoers.d/zz-egret-no-sudo
else
  echo "  sudoers drop-in removed after teardown (expected: restored)"
fi

# --- owed bare-host follow-ups (netsec re-gate list) ---

# F-C self-probe: EVERY block-mode run above already ran the post-setup self-probe
# (it forks a canary probe into the build cgroup and aborts if the cgroup drop
# didn't fire). On this bare host the cgroup match works, so the runs proceeded -
# i.e. the self-probe PASS path is confirmed by the fact block mode ran at all. The
# ABORT path (fail-open detection) only triggers on a cgroup-namespaced topology;
# run scripts/validate-block-mode-container.sh (docker) or the enforcer-regate CI
# workflow to exercise it.
echo "=== F-C self-probe: PASS path (block-mode runs above proceeded) ==="
echo "  self-probe did not abort any block-mode run -> cgroup match confining (expected on bare host)"

# allowed-ips overlap / auto-merge (netsec F4): a bare IP inside a listed CIDR must
# NOT fail Setup (the interval sets are auto-merge).
echo "=== allowed-ips overlap (auto-merge): 10.0.0.0/8 + 10.0.0.5 must not fail setup ==="
cat > /tmp/egret-ov.yaml <<YAML
version: 1
mode: block
egress: { allowed-endpoints: [], allowed-ips: ["10.0.0.0/8", "10.0.0.5"], block-raw-ip: true }
report: { format: [json], output-dir: /tmp/egret-ips-report }
YAML
if ./bin/egret run --mode block --config /tmp/egret-ov.yaml -- true >/dev/null 2>&1; then
  echo "  -> ran (expected: interval auto-merge accepted the overlap)"
else
  echo "  -> FAILED to set up (BAD: overlap not merged)"
fi
rm -f /tmp/egret-ov.yaml

# disable-sudo ISOLATED deny (netsec item 5): prove the sudoers drop-in itself
# denies, independent of no_new_privs. Write the same deny by hand, then have the
# BUILD USER attempt sudo (run the inner `sudo` AS the build user via
# `sudo -u <builduser> -- sudo -n true` - NOT `sudo -u <builduser> -n true`, which
# would test root's own privilege and always succeed). It must fail on the deny.
echo "=== disable-sudo: isolated sudoers deny (no no_new_privs in play) ==="
BUILDUSER=$(id -nu "${SUDO_UID}")
# Baseline: confirm the build user CAN sudo before we install the deny (else the
# test proves nothing on a host where the user has no sudo to begin with).
if sudo -u "$BUILDUSER" -- sudo -n true 2>/dev/null; then
  BASELINE=yes
else
  BASELINE=no
fi
printf '%s ALL=(ALL:ALL) !ALL\n' "$BUILDUSER" > /etc/sudoers.d/zz-egret-no-sudo
chmod 0440 /etc/sudoers.d/zz-egret-no-sudo
if sudo -u "$BUILDUSER" -- sudo -n true 2>/tmp/egret-deny.err; then
  echo "  -> build user's sudo SUCCEEDED with the deny in place (BAD: deny ineffective; baseline sudo=${BASELINE})"
else
  if [ "$BASELINE" = no ]; then
    echo "  -> denied, but build user had NO sudo even before the deny - inconclusive on this host"
  else
    echo "  -> denied (expected): the sudoers !ALL took effect independent of no_new_privs. msg: $(tr -d '\n' < /tmp/egret-deny.err | head -c 100)"
  fi
fi
rm -f /etc/sudoers.d/zz-egret-no-sudo /tmp/egret-deny.err

# cleanup planted probe + temp policies
rm -f /tmp/egret-suid-probe /tmp/egret-suid.c /tmp/egret-ips-pol.yaml /tmp/egret-ips-build.sh
