# Ingest contract (agent → Egret Nest Dashboard)

This is the **only** coupling between the Egret agent and the optional
self-hosted dashboard. The agent produces an **Envelope**; the dashboard
consumes it. The agent has no other knowledge of the server, and when
`EGRET_INGEST_URL` is unset it does nothing here - the dashboard is never
required (see [ROADMAP.md](ROADMAP.md) core invariant).

Source of truth: `internal/ingest` in `Egret`. Wire format: JSON.

## Transport

- The agent `POST`s the Envelope as `application/json` to `EGRET_INGEST_URL`.
- If `EGRET_INGEST_TOKEN` is set, it is sent as `Authorization: Bearer <token>`.
- Any non-2xx response is logged and ignored - a failed POST never fails a build.
- Alternatively, a self-hoster can skip the POST and have their server pull the
  `report.json` artifact via a GitHub `workflow_run` webhook. Same Envelope shape
  applies (wrap the session with the same metadata).

## Envelope (`schema_version: 1`)

```json
{
  "schema_version": 1,
  "producer": "egret",
  "producer_version": "v0.1.0",
  "generated_at": "2026-07-02T10:00:00Z",
  "run": {
    "provider": "github-actions",
    "repository": "NX1X/Egret",
    "sha": "deadbeef...",
    "ref": "refs/heads/main",
    "workflow": "CI",
    "run_id": "123456789",
    "run_attempt": "1",
    "actor": "NX1X"
  },
  "session": { /* the event.Session - see report.json */ }
}
```

- `run.*` fields are populated from the GitHub Actions environment
  (`GITHUB_REPOSITORY`, `GITHUB_SHA`, …); off CI they are empty.
- `session` is exactly the `report.json` structure the agent already writes:
  `connections`, `processes`, `file_writes`, `violations`, `mode`, timing, exit code.

## Compatibility policy

- `schema_version` is bumped **only** on a breaking change.
- Within a major version, changes are **additive** (new optional fields).
  Consumers must ignore unknown fields.
- The dashboard should reject envelopes whose `schema_version` it does not
  support, with a clear error, rather than mis-parse.
