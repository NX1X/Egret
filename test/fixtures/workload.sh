#!/usr/bin/env bash
# A controlled workload to exercise Egret's monitors and enforcer edge cases.
# Wrap it: `sudo egret run --config policy.yaml -- test/fixtures/workload.sh`.
#
# It deliberately mixes allowed and disallowed behaviour so a report/enforcement
# run has something to show. Each step tolerates failure (|| true) so the
# workload itself never aborts the run — Egret's job is to observe/enforce.
set -u

echo "[workload] allowed egress (in a typical allowlist)"
curl -sS -m 15 https://github.com/ >/dev/null || true
curl -sS -m 15 https://registry.npmjs.org/ >/dev/null || true

echo "[workload] disallowed egress (should be flagged/blocked)"
curl -sS -m 10 https://example.com/ >/dev/null || true

echo "[workload] raw-IP egress with no DNS lookup (block-raw-ip target)"
curl -sS -m 10 https://1.1.1.1/ >/dev/null || true

echo "[workload] write to a protected path (should be flagged)"
echo "tampered" > ./.git/egret-test-marker 2>/dev/null || true
rm -f ./.git/egret-test-marker 2>/dev/null || true

echo "[workload] spawn a child process (process-tree observation)"
/bin/sh -c 'true' || true

echo "[workload] done"
