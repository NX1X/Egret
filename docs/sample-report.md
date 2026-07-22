# 🪶 Egret report

> **Mockup** - an illustrative example of `report.md` (and the GitHub job
> summary) produced by `egret run`. Generated reports will look like this; this
> file is documentation, not test output.

- **Command:** `./build.sh --release`
- **Mode:** block
- **Exit code:** 0
- **Duration:** 42.318s
- **Connections:** 6 · **Processes:** 18 · **File writes:** 2 · **Violations:** 2

## ⚠️ Blocked / flagged

| Kind | Reason | Detail | Blocked |
|---|---|---|:--:|
| connection | domain not in allowlist | telemetry.evil.example (203.0.113.7:443/tcp) by node[2244] | ✅ |
| connection | raw-ip egress | 1.1.1.1:443/tcp by curl[2310] with no prior DNS lookup | ✅ |

## 🌐 Connections

| PID | Process | Destination | Port | Proto |
|---|---|---|---|---|
| 2201 | git | github.com (140.82.121.4) | 443 | tcp |
| 2230 | node | registry.npmjs.org (104.16.30.34) | 443 | tcp |
| 2230 | node | objects.githubusercontent.com (185.199.108.133) | 443 | tcp |
| 2244 | node | telemetry.evil.example (203.0.113.7) | 443 | tcp |
| 2310 | curl | 1.1.1.1 | 443 | tcp |
| 2350 | go | proxy.golang.org (142.250.74.17) | 443 | tcp |

## 📝 File writes

| PID | Process | Op | Path |
|---|---|---|---|
| 2400 | postinstall | open-write | /home/runner/work/app/.git/hooks/pre-push |
| 2401 | postinstall | open-write | /home/runner/.ssh/known_hosts |

## 🧬 Processes

| PID | PPID | Process | Filename |
|---|---|---|---|
| 2200 | 1 | build.sh | /usr/bin/bash |
| 2201 | 2200 | git | /usr/bin/git |
| 2230 | 2200 | node | /usr/bin/node |
| 2310 | 2230 | curl | /usr/bin/curl |
