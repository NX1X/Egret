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
#   block-denied   block mode refuses a name that is not on the allowlist, and
#                  the firewall drops a connection to its IP (resolved outside
#                  Egret and passed with curl --resolve, so DNS plays no part).
#   proxy-tcp      the build resolves through the proxy over TCP too.
#   stub-udp/tcp   the build cannot query systemd-resolved (127.0.0.53, and
#                  127.0.0.54 when it answers) itself. Each stub check has a
#                  positive control outside Egret, so a dead stub cannot pass.
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

# Controls, outside Egret. The denied host's IP, for the raw-IP checks.
DENIED_IP="$(dig +short api.github.com A | grep -E '^[0-9.]+$' | head -1)"
if [ -z "${DENIED_IP}" ]; then echo "::error::cannot resolve api.github.com outside Egret"; exit 1; fi
# ...and it must be reachable outside Egret, or "blocked" inside proves nothing.
curl -fsS --connect-timeout 8 --max-time 10 -o /dev/null \
    --resolve "api.github.com:443:${DENIED_IP}" https://api.github.com \
  || { echo "::error::control: ${DENIED_IP} is not reachable outside Egret"; exit 1; }
# The stubs must answer outside Egret, or "blocked" inside proves nothing.
dig @127.0.0.53 example.com +time=2 +tries=1 >/dev/null 2>&1 \
  || { echo "::error::control: 127.0.0.53 does not answer outside Egret"; exit 1; }
STUB54=no
if dig @127.0.0.54 example.com +time=2 +tries=1 >/dev/null 2>&1; then STUB54=yes; fi
echo "controls: api.github.com=${DENIED_IP}, 127.0.0.54 answers=${STUB54}"

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
  echo "MARK denied-name=reached"; else echo "MARK denied-name=blocked"; fi
if curl -fsS --connect-timeout 8 --max-time 10 -o /dev/null \
    --resolve "api.github.com:443:${DENIED_IP}" https://api.github.com; then
  echo "MARK denied-ip=reached"; else echo "MARK denied-ip=blocked"; fi
# No @server: the default resolver is the pinned proxy.
if [ -n "$(dig +tcp +short example.com A +time=3 +tries=1 2>/dev/null)" ]; then
  echo "MARK proxy-tcp=ok"; else echo "MARK proxy-tcp=failed"; fi
# dig exits 0 on ANY reply (even REFUSED) and 9 when no server answered.
if dig @127.0.0.53 example.com +time=2 +tries=1 >/dev/null 2>&1; then
  echo "MARK stub-udp=reached"; else echo "MARK stub-udp=blocked"; fi
if dig @127.0.0.53 example.com +tcp +time=2 +tries=1 >/dev/null 2>&1; then
  echo "MARK stub-tcp=reached"; else echo "MARK stub-tcp=blocked"; fi
if [ "${STUB54}" = yes ]; then
  if dig @127.0.0.54 example.com +time=2 +tries=1 >/dev/null 2>&1; then
    echo "MARK stub54=reached"; else echo "MARK stub54=blocked"; fi
else
  echo "MARK stub54=blocked"
fi
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
# sudo resets the environment, so put the control values into the script.
sed -i "1a DENIED_IP='${DENIED_IP}'; STUB54='${STUB54}'" "${WORK}/block-build.sh"

sudo "${EGRET}" run --config "${WORK}/block.yaml" --output-dir "${WORK}/block" -- \
  bash "${WORK}/block-build.sh" 2>&1 | tee "${WORK}/block.log"

mark() { grep -m1 "^MARK ${1}=" "${WORK}/block.log" | cut -d= -f2; }
expect() {
  local got; got="$(mark "${1}")"
  if [ "${got}" = "${2}" ]; then pass "block-${1}"
  else fail "block-${1}" "got '${got:-<no marker>}', want '${2}'"; fi
}
expect allowed ok
expect denied-name blocked
expect denied-ip blocked
expect proxy-tcp ok
expect stub-udp blocked
expect stub-tcp blocked
expect stub54 blocked
expect loopback ok
got="$(report_domain "${WORK}/block")"
if [ "${got}" = "example.com" ]; then pass block-label
else fail block-label "curl's connection is labeled '${got}', want 'example.com'"; fi

# 3. Two block runs at the same time. Run 1 signals it is up, waits until run 2
#    has finished, then connects to the denied host's IP directly. The proxy
#    plays no part in that request, so only run 1's own nft filter can stop it:
#    if run 2 removed that filter, the request goes through.
ready="${WORK}/run1.ready"
done2="${WORK}/run2.done"
cat > "${WORK}/run1-build.sh" <<BUILD
set -u
touch "${ready}"
for _ in \$(seq 1 120); do [ -e "${done2}" ] && break; sleep 0.5; done
[ -e "${done2}" ] || { echo "MARK run1=timeout"; exit 0; }
if curl -fsS --connect-timeout 8 --max-time 10 -o /dev/null \
    --resolve "api.github.com:443:${DENIED_IP}" https://api.github.com; then
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
