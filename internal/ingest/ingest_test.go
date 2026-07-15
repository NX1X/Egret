package ingest

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/NX1X/Egret/internal/event"
)

func TestRunMetaFromEnv(t *testing.T) {
	t.Setenv("GITHUB_ACTIONS", "true")
	t.Setenv("GITHUB_REPOSITORY", "NX1X/Egret")
	t.Setenv("GITHUB_SHA", "deadbeef")
	t.Setenv("GITHUB_RUN_ID", "42")

	m := RunMetaFromEnv()
	if m.Provider != "github-actions" {
		t.Errorf("provider = %q", m.Provider)
	}
	if m.Repository != "NX1X/Egret" || m.SHA != "deadbeef" || m.RunID != "42" {
		t.Errorf("meta = %+v", m)
	}
}

func TestNewEnvelope(t *testing.T) {
	s := &event.Session{Mode: "block"}
	env := NewEnvelope(s, RunMeta{Repository: "a/b"}, "v0.1.0")

	if env.SchemaVersion != SchemaVersion {
		t.Errorf("schema_version = %d, want %d", env.SchemaVersion, SchemaVersion)
	}
	if env.Producer != "egret" || env.ProducerVersion != "v0.1.0" {
		t.Errorf("producer = %+v", env)
	}
	if env.GeneratedAt.IsZero() {
		t.Error("generated_at not set")
	}
	if env.Session != s {
		t.Error("session not attached")
	}

	// Round-trips through JSON with the expected wire keys.
	b, _ := json.Marshal(env)
	var raw map[string]any
	json.Unmarshal(b, &raw)
	if _, ok := raw["schema_version"]; !ok {
		t.Errorf("missing schema_version key: %s", b)
	}
}

func TestPostSuccess(t *testing.T) {
	var gotAuth, gotType string
	var gotEnv Envelope
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotType = r.Header.Get("Content-Type")
		b, _ := io.ReadAll(r.Body)
		json.Unmarshal(b, &gotEnv)
		w.WriteHeader(http.StatusAccepted)
	}))
	defer srv.Close()

	env := NewEnvelope(&event.Session{Mode: "audit"}, RunMeta{Repository: "a/b"}, "v1")
	if err := Post(context.Background(), srv.URL, "sekret", env); err != nil {
		t.Fatalf("Post: %v", err)
	}
	if gotAuth != "Bearer sekret" {
		t.Errorf("auth header = %q", gotAuth)
	}
	if gotType != "application/json" {
		t.Errorf("content-type = %q", gotType)
	}
	if gotEnv.Run.Repository != "a/b" {
		t.Errorf("server received wrong envelope: %+v", gotEnv.Run)
	}
}

func TestPostNon2xxIsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "nope", http.StatusForbidden)
	}))
	defer srv.Close()

	err := Post(context.Background(), srv.URL, "", NewEnvelope(&event.Session{}, RunMeta{}, ""))
	if err == nil {
		t.Fatal("expected error on 403")
	}
}

// TestPostRefusesCleartextTokenToRemote: a bearer token must never go out over
// plaintext http to a non-loopback host — Post refuses before making the request.
func TestPostRefusesCleartextTokenToRemote(t *testing.T) {
	err := Post(context.Background(), "http://dashboard.example.com/ingest", "sekret",
		NewEnvelope(&event.Session{}, RunMeta{}, ""))
	if err == nil {
		t.Fatal("expected refusal to send a token over cleartext http to a remote host")
	}
}

// TestPostAllowsHTTPToLoopback: http is fine to localhost (a same-host dashboard),
// where nothing traverses a network — the httptest server binds 127.0.0.1.
func TestPostAllowsHTTPToLoopback(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusAccepted)
	}))
	defer srv.Close()
	if err := Post(context.Background(), srv.URL, "sekret", NewEnvelope(&event.Session{}, RunMeta{}, "")); err != nil {
		t.Fatalf("http to loopback should be allowed: %v", err)
	}
}

// TestPostRejectsNonHTTPScheme: a non-http(s) scheme is refused outright.
func TestPostRejectsNonHTTPScheme(t *testing.T) {
	if err := Post(context.Background(), "ftp://example.com/x", "", NewEnvelope(&event.Session{}, RunMeta{}, "")); err == nil {
		t.Fatal("expected refusal of a non-http(s) scheme")
	}
}

func TestPostNoTokenOmitsAuth(t *testing.T) {
	var hadAuth bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, hadAuth = r.Header["Authorization"]
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	Post(context.Background(), srv.URL, "", NewEnvelope(&event.Session{}, RunMeta{}, ""))
	if hadAuth {
		t.Error("Authorization header should be absent when token is empty")
	}
}
