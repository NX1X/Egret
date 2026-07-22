package github

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
)

func TestCreateCheckRun(t *testing.T) {
	var gotBody map[string]any
	var gotAuth, gotPath, gotMethod, gotAPIVer string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotAPIVer = r.Header.Get("X-GitHub-Api-Version")
		gotMethod, gotPath = r.Method, r.URL.Path
		_ = json.NewDecoder(r.Body).Decode(&gotBody)
		w.WriteHeader(http.StatusCreated)
		w.Write([]byte(`{}`))
	}))
	defer ts.Close()
	t.Setenv("GITHUB_API_URL", ts.URL)

	// Base-URL validation: an http (non-https) URL must be rejected, falling
	// back to the public API default (so we don't accidentally hit ts here).
	if got := NewClient("x").baseURL; got != ts.URL {
		t.Fatalf("https override not honored: %q", got)
	}

	c := NewClient("tok")
	err := c.CreateCheckRun(context.Background(), "o", "r", CheckRun{
		Name: "egret", HeadSHA: "sha123", Conclusion: "failure",
		Title: "2 violations", Summary: "details",
	})
	if err != nil {
		t.Fatalf("CreateCheckRun: %v", err)
	}
	if gotMethod != "POST" || gotPath != "/repos/o/r/check-runs" {
		t.Errorf("request = %s %s", gotMethod, gotPath)
	}
	if gotAuth != "Bearer tok" || gotAPIVer != "2022-11-28" {
		t.Errorf("headers auth=%q apiver=%q", gotAuth, gotAPIVer)
	}
	if gotBody["conclusion"] != "failure" || gotBody["head_sha"] != "sha123" || gotBody["status"] != "completed" {
		t.Errorf("body = %+v", gotBody)
	}
}

func TestNewClientRejectsNonHTTPS(t *testing.T) {
	t.Setenv("GITHUB_API_URL", "http://evil.example/api")
	if got := NewClient("t").baseURL; got != "https://api.github.com" {
		t.Errorf("non-https override should be ignored; baseURL = %q", got)
	}
}

func TestUpsertStickyComment(t *testing.T) {
	const marker = "<!-- egret-report -->"
	existing := false
	var lastMethod string
	mux := http.NewServeMux()
	mux.HandleFunc("GET /repos/o/r/issues/5/comments", func(w http.ResponseWriter, _ *http.Request) {
		if existing {
			w.Write([]byte(`[{"id":99,"body":"` + marker + ` old","user":{"type":"Bot"}}]`))
		} else {
			w.Write([]byte(`[]`))
		}
	})
	mux.HandleFunc("POST /repos/o/r/issues/5/comments", func(w http.ResponseWriter, _ *http.Request) {
		lastMethod = "POST"
		w.WriteHeader(http.StatusCreated)
		w.Write([]byte(`{}`))
	})
	mux.HandleFunc("PATCH /repos/o/r/issues/comments/99", func(w http.ResponseWriter, _ *http.Request) {
		lastMethod = "PATCH"
		w.Write([]byte(`{}`))
	})
	ts := httptest.NewServer(mux)
	defer ts.Close()
	t.Setenv("GITHUB_API_URL", ts.URL)
	c := NewClient("tok")

	if err := c.UpsertStickyComment(context.Background(), "o", "r", 5, marker, "hi"); err != nil {
		t.Fatalf("create: %v", err)
	}
	if lastMethod != "POST" {
		t.Errorf("first upsert = %s, want POST", lastMethod)
	}
	existing = true
	if err := c.UpsertStickyComment(context.Background(), "o", "r", 5, marker, "hi2"); err != nil {
		t.Fatalf("update: %v", err)
	}
	if lastMethod != "PATCH" {
		t.Errorf("second upsert = %s, want PATCH", lastMethod)
	}
}

// A marked comment authored by a non-bot (a user who pre-planted the marker)
// must NOT be adopted - the run posts its own comment instead (hijack defense).
func TestStickyCommentIgnoresNonBotAuthor(t *testing.T) {
	const marker = "<!-- egret-report -->"
	var lastMethod string
	mux := http.NewServeMux()
	mux.HandleFunc("GET /repos/o/r/issues/5/comments", func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte(`[{"id":99,"body":"` + marker + `","user":{"type":"User","login":"attacker"}}]`))
	})
	mux.HandleFunc("POST /repos/o/r/issues/5/comments", func(w http.ResponseWriter, _ *http.Request) {
		lastMethod = "POST"
		w.WriteHeader(http.StatusCreated)
		w.Write([]byte(`{}`))
	})
	ts := httptest.NewServer(mux)
	defer ts.Close()
	t.Setenv("GITHUB_API_URL", ts.URL)
	if err := NewClient("t").UpsertStickyComment(context.Background(), "o", "r", 5, marker, "hi"); err != nil {
		t.Fatalf("upsert: %v", err)
	}
	if lastMethod != "POST" {
		t.Errorf("attacker-planted comment should not be hijacked; method = %s", lastMethod)
	}
}

// A marked comment beyond the first page is still found (pagination).
func TestStickyCommentPaginates(t *testing.T) {
	const marker = "<!-- egret-report -->"
	var lastMethod string
	mux := http.NewServeMux()
	mux.HandleFunc("GET /repos/o/r/issues/5/comments", func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Query().Get("page") {
		case "1":
			parts := make([]string, 100)
			for i := range parts {
				parts[i] = `{"id":` + strconv.Itoa(i) + `,"body":"noise","user":{"type":"Bot"}}`
			}
			w.Write([]byte("[" + strings.Join(parts, ",") + "]"))
		case "2":
			w.Write([]byte(`[{"id":999,"body":"` + marker + `","user":{"type":"Bot"}}]`))
		default:
			w.Write([]byte(`[]`))
		}
	})
	mux.HandleFunc("PATCH /repos/o/r/issues/comments/999", func(w http.ResponseWriter, _ *http.Request) {
		lastMethod = "PATCH"
		w.Write([]byte(`{}`))
	})
	ts := httptest.NewServer(mux)
	defer ts.Close()
	t.Setenv("GITHUB_API_URL", ts.URL)
	if err := NewClient("t").UpsertStickyComment(context.Background(), "o", "r", 5, marker, "hi"); err != nil {
		t.Fatalf("upsert: %v", err)
	}
	if lastMethod != "PATCH" {
		t.Errorf("marked comment on page 2 not found; method = %s (want PATCH)", lastMethod)
	}
}

func TestUpsertDashboardIssue(t *testing.T) {
	const marker = "<!-- egret-dashboard -->"
	existing := false
	var lastMethod string
	mux := http.NewServeMux()
	mux.HandleFunc("GET /repos/o/r/issues", func(w http.ResponseWriter, _ *http.Request) {
		if existing {
			w.Write([]byte(`[{"number":7,"title":"x","body":"` + marker + `","user":{"type":"Bot"}}]`))
		} else {
			w.Write([]byte(`[]`))
		}
	})
	mux.HandleFunc("POST /repos/o/r/issues", func(w http.ResponseWriter, _ *http.Request) {
		lastMethod = "POST"
		w.WriteHeader(http.StatusCreated)
		w.Write([]byte(`{"number":7}`))
	})
	mux.HandleFunc("PATCH /repos/o/r/issues/7", func(w http.ResponseWriter, _ *http.Request) {
		lastMethod = "PATCH"
		w.Write([]byte(`{}`))
	})
	ts := httptest.NewServer(mux)
	defer ts.Close()
	t.Setenv("GITHUB_API_URL", ts.URL)
	c := NewClient("tok")

	n, err := c.UpsertDashboardIssue(context.Background(), "o", "r", "Egret Dashboard", marker, "body")
	if err != nil || n != 7 || lastMethod != "POST" {
		t.Fatalf("create: n=%d method=%s err=%v", n, lastMethod, err)
	}
	existing = true
	n, err = c.UpsertDashboardIssue(context.Background(), "o", "r", "Egret Dashboard", marker, "body2")
	if err != nil || n != 7 || lastMethod != "PATCH" {
		t.Fatalf("update: n=%d method=%s err=%v", n, lastMethod, err)
	}
}

// An entry returned by /issues that is actually a PR (has pull_request) must be
// skipped even if it carries the marker.
func TestDashboardSkipsPullRequests(t *testing.T) {
	const marker = "<!-- egret-dashboard -->"
	var lastMethod string
	mux := http.NewServeMux()
	mux.HandleFunc("GET /repos/o/r/issues", func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte(`[{"number":3,"title":"pr","body":"` + marker + `","user":{"type":"Bot"},"pull_request":{}}]`))
	})
	mux.HandleFunc("POST /repos/o/r/issues", func(w http.ResponseWriter, _ *http.Request) {
		lastMethod = "POST"
		w.WriteHeader(http.StatusCreated)
		w.Write([]byte(`{"number":8}`))
	})
	ts := httptest.NewServer(mux)
	defer ts.Close()
	t.Setenv("GITHUB_API_URL", ts.URL)
	n, err := NewClient("t").UpsertDashboardIssue(context.Background(), "o", "r", "Egret Dashboard", marker, "b")
	if err != nil || n != 8 || lastMethod != "POST" {
		t.Fatalf("should skip PR and create issue: n=%d method=%s err=%v", n, lastMethod, err)
	}
}

func TestOpenFilePR(t *testing.T) {
	var putContent, prBase, prHead string
	mux := http.NewServeMux()
	mux.HandleFunc("GET /repos/o/r", func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte(`{"default_branch":"main"}`))
	})
	mux.HandleFunc("GET /repos/o/r/git/ref/heads/main", func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte(`{"object":{"sha":"basesha"}}`))
	})
	mux.HandleFunc("POST /repos/o/r/git/refs", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusCreated)
		w.Write([]byte(`{}`))
	})
	mux.HandleFunc("GET /repos/o/r/contents/.github/egret-policy.yaml", func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "not found", http.StatusNotFound) // file doesn't exist yet
	})
	mux.HandleFunc("PUT /repos/o/r/contents/.github/egret-policy.yaml", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Content string `json:"content"`
		}
		json.NewDecoder(r.Body).Decode(&body)
		putContent = body.Content
		w.WriteHeader(http.StatusCreated)
		w.Write([]byte(`{}`))
	})
	mux.HandleFunc("POST /repos/o/r/pulls", func(w http.ResponseWriter, r *http.Request) {
		var body struct{ Head, Base string }
		json.NewDecoder(r.Body).Decode(&body)
		prHead, prBase = body.Head, body.Base
		w.WriteHeader(http.StatusCreated)
		w.Write([]byte(`{"number":42}`))
	})
	ts := httptest.NewServer(mux)
	defer ts.Close()
	t.Setenv("GITHUB_API_URL", ts.URL)

	n, err := NewClient("tok").OpenFilePR(context.Background(), "o", "r",
		".github/egret-policy.yaml", "egret/update-allowlist", "",
		"title", "body", "msg", []byte("version: 1\n"))
	if err != nil {
		t.Fatalf("OpenFilePR: %v", err)
	}
	if n != 42 {
		t.Errorf("pr number = %d, want 42", n)
	}
	if putContent == "" {
		t.Error("file content was not PUT")
	}
	if prHead != "egret/update-allowlist" || prBase != "main" {
		t.Errorf("PR head/base = %s/%s", prHead, prBase)
	}
}

func TestOpenFilePRReusesExistingPR(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /repos/o/r/git/ref/heads/main", func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte(`{"object":{"sha":"basesha"}}`))
	})
	mux.HandleFunc("POST /repos/o/r/git/refs", func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "exists", http.StatusUnprocessableEntity) // branch already exists
	})
	mux.HandleFunc("PATCH /repos/o/r/git/refs/heads/egret/update-allowlist", func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte(`{}`))
	})
	mux.HandleFunc("GET /repos/o/r/contents/p.yaml", func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte(`{"sha":"oldblob"}`)) // file exists -> update
	})
	mux.HandleFunc("PUT /repos/o/r/contents/p.yaml", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{}`))
	})
	mux.HandleFunc("POST /repos/o/r/pulls", func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "A pull request already exists", http.StatusUnprocessableEntity)
	})
	mux.HandleFunc("GET /repos/o/r/pulls", func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte(`[{"number":7}]`))
	})
	ts := httptest.NewServer(mux)
	defer ts.Close()
	t.Setenv("GITHUB_API_URL", ts.URL)

	n, err := NewClient("t").OpenFilePR(context.Background(), "o", "r",
		"p.yaml", "egret/update-allowlist", "main", "t", "b", "m", []byte("x"))
	if err != nil {
		t.Fatalf("OpenFilePR: %v", err)
	}
	if n != 7 {
		t.Errorf("should reuse existing PR #7, got %d", n)
	}
}

func TestGetFileContent(t *testing.T) {
	want := "version: 1\nmode: block\n"
	mux := http.NewServeMux()
	mux.HandleFunc("GET /repos/o/r/contents/.egret-policy.yaml", func(w http.ResponseWriter, _ *http.Request) {
		enc := base64.StdEncoding.EncodeToString([]byte(want))
		// GitHub wraps base64 at 60 cols; emulate with a newline to test stripping.
		w.Write([]byte(`{"encoding":"base64","content":"` + enc[:4] + "\\n" + enc[4:] + `"}`))
	})
	ts := httptest.NewServer(mux)
	defer ts.Close()
	t.Setenv("GITHUB_API_URL", ts.URL)

	got, err := NewClient("t").GetFileContent(context.Background(), "o", "r", ".egret-policy.yaml", "")
	if err != nil {
		t.Fatalf("GetFileContent: %v", err)
	}
	if string(got) != want {
		t.Errorf("content = %q, want %q", got, want)
	}
}

func TestDoReturnsErrorOnNon2xx(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "forbidden", http.StatusForbidden)
	}))
	defer ts.Close()
	t.Setenv("GITHUB_API_URL", ts.URL)
	c := NewClient("tok")
	if err := c.CreateCheckRun(context.Background(), "o", "r", CheckRun{}); err == nil {
		t.Error("expected error on 403")
	}
}
