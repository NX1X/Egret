#!/usr/bin/env bash
# End-to-end test of DNS correlation and loopback DNS confinement on a real
# runner (GitHub-hosted ubuntu, systemd-resolved stub at 127.0.0.53).
#
#   ./scripts/e2e-dns.sh ./bin/egret
#
# Run it as the normal runner user: it calls `sudo egret run`, so block mode
# drops the build to this user (SUDO_UID). Needs sudo, nft, dig, jq, python3.
#
# Checks:
#   audit-label    audit mode labels the build's connection with its domain.
#   block-allowed  block mode lets an allowlisted host through and labels it.
#   block-denied   block mode stops a host that is not on the allowlist.
#   stub-udp/tcp   the build cannot query systemd-resolved (127.0.0.53) itself.
#   loopback       the build can still talk to a local server on 127.0.0.1.
#   concurrent     a second block run does not remove the first run's filter.
#
# Every check runs; the script exits 1 if any of them failed.
set -uo pipefail

EGRET="$(realpath "${1:?usage: e2e-dns.sh <path-to-egret>}")"
WORK="$(mktemp -d "${RUNNER_TEMP:-/tmp}/egret-e2e-dns.XXXXXX")"
chmod 0755 "${WORK}"
FAILED=0

pass() { echo "PASS ${1}"; }
fail() { echo "::error::FAIL ${1}: ${2}"; FAILED=1; }

for tool in sudo nft dig jq python3 curl; do
  command -v "${tool}" >/dev/null || { echo "::error::${tool} not found"; exit 1; }
done

cat > "${WORK}/block.yaml" <<'YAML'
version: 1
mode: block
egress:
  allowed-endpoints:
    - example.com
  block-raw-ip: true
YAML

# report_domain DIR prints the domain Egret recorded for curl's port-443 connection.
report_domain() {
  sudo jq -r '[.connections[]? | select(.comm == "curl" and .dport == 443) | .domain // ""][0] // ""' \
    "${1}/report.json" 2>/dev/null
}

# 1. Audit mode labels the connection.
sudo "${EGRET}" run --mode audit --output-dir "${WORK}/audit" -- \
  curl -fsS --connect-timeout 10 --max-time 30 -o /dev/null https://example.com
got="$(report_domain "${WORK}/audit")"
if [ "${got}" = "example.com" ]; then pass audit-label
else fail audit-label "curl's connection is labeled '${got}', want 'example.com'"; fi

# 2. Block mode, one run with every in-build check. The build prints one marker
#    per check; the script asserts on the markers after the run.
cat > "${WORK}/block-build.sh" <<'BUILD'
set -u
if curl -fsS --connect-timeout 10 --max-time 20 -o /dev/null https://example.com; then
  echo "MARK allowed=ok"; else echo "MARK allowed=failed"; fi
if curl -fsS --connect-timeout 10 --max-time 20 -o /dev/null https://api.github.com; then
  echo "MARK denied=reached"; else echo "MARK denied=blocked"; fi
# dig exits 0 on ANY reply (even REFUSED) and 9 when no server answered.
if dig @127.0.0.53 example.com +time=2 +tries=1 >/dev/null 2>&1; then
  echo "MARK stub-udp=reached"; else echo "MARK stub-udp=blocked"; fi
if dig @127.0.0.53 example.com +tcp +time=2 +tries=1 >/dev/null 2>&1; then
  echo "MARK stub-tcp=reached"; else echo "MARK stub-tcp=blocked"; fi
python3 -m http.server 18765 --bind 127.0.0.1 >/dev/null 2>&1 &
srv=$!
ok=failed
for _ in 1 2 3 4 5 6 7 8 9 10; do
  if curl -fsS --max-time 2 -o /dev/null http://127.0.0.1:18765/; then ok=ok; break; fi
  sleep 0.5
done
kill "${srv}" 2>/dev/null
echo "MARK loopback=${ok}"
BUILD

sudo "${EGRET}" run --config "${WORK}/block.yaml" --output-dir "${WORK}/block" -- \
  bash "${WORK}/block-build.sh" 2>&1 | tee "${WORK}/block.log"

mark() { grep -m1 "^MARK ${1}=" "${WORK}/block.log" | cut -d= -f2; }
expect() {
  local got; got="$(mark "${1}")"
  if [ "${got}" = "${2}" ]; then pass "block-${1}"
  else fail "block-${1}" "got '${got:-<no marker>}', want '${2}'"; fi
}
expect allowed ok
expect denied blocked
expect stub-udp blocked
expect stub-tcp blocked
expect loopback ok
got="$(report_domain "${WORK}/block")"
if [ "${got}" = "example.com" ]; then pass block-label
else fail block-label "curl's connection is labeled '${got}', want 'example.com'"; fi

# 3. Two block runs at the same time. Run 1 signals it is up, waits until run 2
#    has finished, then tries a disallowed host. If run 2's teardown removed
#    run 1's filter, that request goes through.
ready="${WORK}/run1.ready"
done2="${WORK}/run2.done"
cat > "${WORK}/run1-build.sh" <<BUILD
set -u
touch "${ready}"
for _ in \$(seq 1 120); do [ -e "${done2}" ] && break; sleep 0.5; done
[ -e "${done2}" ] || { echo "MARK run1=timeout"; exit 0; }
if curl -fsS --connect-timeout 10 --max-time 15 -o /dev/null https://api.github.com; then
  echo "MARK run1=reached"; else echo "MARK run1=blocked"; fi
if curl -fsS --connect-timeout 10 --max-time 20 -o /dev/null https://example.com; then
  echo "MARK run1-allowed=ok"; else echo "MARK run1-allowed=failed"; fi
BUILD

# The logs belong to the runner user on purpose (SC2024: sudo skips redirects).
# shellcheck disable=SC2024
sudo "${EGRET}" run --config "${WORK}/block.yaml" --output-dir "${WORK}/run1" -- \
  bash "${WORK}/run1-build.sh" > "${WORK}/run1.log" 2>&1 &
run1=$!
for _ in $(seq 1 120); do [ -e "${ready}" ] && break; sleep 0.5; done
if [ -e "${ready}" ]; then
  # shellcheck disable=SC2024
  if sudo "${EGRET}" run --config "${WORK}/block.yaml" --output-dir "${WORK}/run2" -- \
      curl -fsS --connect-timeout 10 --max-time 20 -o /dev/null https://example.com \
      > "${WORK}/run2.log" 2>&1; then
    pass concurrent-run2
  else
    fail concurrent-run2 "the second block run failed"; cat "${WORK}/run2.log"
  fi
else
  fail concurrent "run 1 never became ready"; cat "${WORK}/run1.log"
fi
touch "${done2}"
wait "${run1}"
cat "${WORK}/run1.log"
r1="$(grep -m1 '^MARK run1=' "${WORK}/run1.log" | cut -d= -f2)"
if [ "${r1}" = "blocked" ]; then pass concurrent-run1-still-confined
else fail concurrent-run1-still-confined "got '${r1:-<no marker>}', want 'blocked'"; fi
r1a="$(grep -m1 '^MARK run1-allowed=' "${WORK}/run1.log" | cut -d= -f2)"
if [ "${r1a}" = "ok" ]; then pass concurrent-run1-allowed
else fail concurrent-run1-allowed "got '${r1a:-<no marker>}', want 'ok'"; fi

# 4. Nothing left behind: no Egret nft table, no build cgroup.
if sudo nft list tables 2>/dev/null | grep -q egret; then
  fail cleanup "an Egret nft table is still installed"; sudo nft list tables
else pass cleanup-nft; fi
if compgen -G "/sys/fs/cgroup/egret-run-*" >/dev/null; then
  fail cleanup "an Egret build cgroup is still present"
else pass cleanup-cgroup; fi

exit "${FAILED}"
