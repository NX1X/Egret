// Package ingest defines the versioned contract between the Egret agent (the
// producer) and the optional Egret Nest Dashboard (the consumer), plus the
// optional POST that ships a run to a self-hosted server.
//
// This is the ONLY coupling between the agent and any server: the agent writes
// an Envelope and, if EGRET_INGEST_URL is set, POSTs it. When the URL is unset
// the agent behaves exactly as before - the dashboard is never required.
//
// See docs/ingest-contract.md. Standard library only, per the dependency policy.
package ingest

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/NX1X/Egret/internal/event"
)

// SchemaVersion is the ingest contract version. Bump only on a breaking change;
// additive fields within a major do not.
const SchemaVersion = 1

// Envelope wraps a session with the metadata a dashboard needs to attribute it.
type Envelope struct {
	SchemaVersion   int            `json:"schema_version"`
	Producer        string         `json:"producer"`
	ProducerVersion string         `json:"producer_version,omitempty"`
	GeneratedAt     time.Time      `json:"generated_at"`
	Run             RunMeta        `json:"run"`
	Session         *event.Session `json:"session"`
}

// RunMeta identifies where a run happened. Fields are best-effort; all optional
// except as populated by the CI provider.
type RunMeta struct {
	Provider   string `json:"provider,omitempty"` // e.g. "github-actions"
	Repository string `json:"repository,omitempty"`
	SHA        string `json:"sha,omitempty"`
	Ref        string `json:"ref,omitempty"`
	Workflow   string `json:"workflow,omitempty"`
	RunID      string `json:"run_id,omitempty"`
	RunAttempt string `json:"run_attempt,omitempty"`
	Actor      string `json:"actor,omitempty"`
}

// RunMetaFromEnv populates RunMeta from GitHub Actions environment variables.
// Off CI it returns a zero-ish RunMeta (all fields empty).
func RunMetaFromEnv() RunMeta {
	m := RunMeta{
		Repository: os.Getenv("GITHUB_REPOSITORY"),
		SHA:        os.Getenv("GITHUB_SHA"),
		Ref:        os.Getenv("GITHUB_REF"),
		Workflow:   os.Getenv("GITHUB_WORKFLOW"),
		RunID:      os.Getenv("GITHUB_RUN_ID"),
		RunAttempt: os.Getenv("GITHUB_RUN_ATTEMPT"),
		Actor:      os.Getenv("GITHUB_ACTOR"),
	}
	if os.Getenv("GITHUB_ACTIONS") == "true" {
		m.Provider = "github-actions"
	}
	return m
}

// NewEnvelope builds an Envelope for a finished session.
func NewEnvelope(s *event.Session, meta RunMeta, producerVersion string) *Envelope {
	return &Envelope{
		SchemaVersion:   SchemaVersion,
		Producer:        "egret",
		ProducerVersion: producerVersion,
		GeneratedAt:     time.Now().UTC(),
		Run:             meta,
		Session:         s,
	}
}

// Post ships the envelope to url as JSON. token, when non-empty, is sent as a
// Bearer token. A non-2xx response is an error. This is best-effort: callers
// should log failures but never fail the build over ingest.
func Post(ctx context.Context, endpoint, token string, env *Envelope) error {
	// Never send the bearer token (or run metadata) in cleartext over the network.
	// Require https, except to a loopback host where http is safe (a dashboard on
	// the same machine, common for local testing). This is fail-closed: an
	// http:// URL to a remote host is refused rather than leaking the token.
	if err := requireSecureEndpoint(endpoint, token); err != nil {
		return err
	}
	body, err := json.Marshal(env)
	if err != nil {
		return fmt.Errorf("marshalling envelope: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("building request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "egret")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("posting to %s: %w", endpoint, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		snippet, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("ingest %s returned %s: %s", endpoint, resp.Status, bytes.TrimSpace(snippet))
	}
	return nil
}

// requireSecureEndpoint enforces that the ingest endpoint is https, so the bearer
// token and run metadata are never sent in cleartext. http is permitted only to a
// loopback host (a dashboard on the same machine, where nothing traverses a real
// network interface); a remote http endpoint is refused.
func requireSecureEndpoint(endpoint, token string) error {
	u, err := url.Parse(endpoint)
	if err != nil {
		return fmt.Errorf("ingest url %q is not parseable: %w", endpoint, err)
	}
	if u.Scheme == "https" {
		return nil
	}
	if u.Scheme != "http" {
		return fmt.Errorf("ingest url %q must be https (or http to localhost); got scheme %q", endpoint, u.Scheme)
	}
	// http is only acceptable to loopback.
	host := u.Hostname()
	if host == "localhost" {
		return nil
	}
	if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
		return nil
	}
	if token != "" {
		return fmt.Errorf("refusing to send the ingest bearer token in cleartext to %q - use https", endpoint)
	}
	return fmt.Errorf("ingest url %q must be https (http is only allowed to localhost)", endpoint)
}
