// Package github is a minimal GitHub REST client for posting Egret results -
// check runs, sticky PR comments, and the security dashboard issue. It uses only
// the standard library (per the dependency policy) and a caller-supplied token
// (a GitHub App installation token or the Actions GITHUB_TOKEN).
//
// The base URL is validated and defaults to the public API (or a vetted
// GITHUB_API_URL for GHES); path segments are escaped. There is no
// user-controlled destination host - no SSRF, and the token only ever travels
// in the Authorization header over HTTPS.
package github

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

const (
	maxRespBytes = 5 << 20 // cap decoded response bodies (memory safety)
	maxPages     = 10      // cap list pagination at 10*100 = 1000 items
)

// Client talks to the GitHub REST API with a bearer token.
type Client struct {
	token   string
	baseURL string
	http    *http.Client
}

// NewClient builds a client. The base URL comes from GITHUB_API_URL (set on
// GitHub Enterprise + in Actions) but is only honored when it is https (or http
// to loopback, for tests/local proxies) - otherwise the safe public-API default
// is used, so a misconfigured or tampered env var can never send the token to a
// plaintext or attacker-controlled host.
func NewClient(token string) *Client {
	base := "https://api.github.com"
	if v := os.Getenv("GITHUB_API_URL"); v != "" {
		if u, err := url.Parse(v); err == nil && u.Host != "" && allowedAPIURL(u) {
			base = strings.TrimRight(v, "/")
		}
	}
	return &Client{
		token:   token,
		baseURL: base,
		http:    &http.Client{Timeout: 15 * time.Second},
	}
}

// allowedAPIURL permits https to any host, and http only to loopback (the token
// never leaves the machine in that case - used by tests and local proxies).
func allowedAPIURL(u *url.URL) bool {
	if u.Scheme == "https" {
		return true
	}
	if u.Scheme == "http" {
		host := u.Hostname()
		if host == "localhost" {
			return true
		}
		if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
			return true
		}
	}
	return false
}

// do issues an authenticated JSON request. If out is non-nil the (size-capped)
// response body is decoded into it. Non-2xx responses become errors with a short
// body snippet. The token appears only in the Authorization header - never in a
// URL or error message.
func (c *Client) newReq(ctx context.Context, method, path string, body any) (*http.Request, error) {
	var rdr io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("marshalling request: %w", err)
		}
		rdr = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, rdr)
	if err != nil {
		return nil, fmt.Errorf("%s %s: %w", method, path, err)
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	req.Header.Set("User-Agent", "egret")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	return req, nil
}

// do issues a request and enforces a 2xx status (status returns the raw code for
// callers that must handle e.g. 404/422).
func (c *Client) do(ctx context.Context, method, path string, body, out any) error {
	_, err := c.status(ctx, method, path, body, out)
	return err
}

// status sends the request, decodes out on a 2xx, and returns the status code.
// On a non-2xx it returns the code with a nil error (so callers can branch) but
// still surfaces a message via a sentinel-free error only for transport issues.
func (c *Client) status(ctx context.Context, method, path string, body, out any) (int, error) {
	req, err := c.newReq(ctx, method, path, body)
	if err != nil {
		return 0, err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return 0, fmt.Errorf("%s %s: %w", method, path, err)
	}
	defer func() {
		io.Copy(io.Discard, io.LimitReader(resp.Body, maxRespBytes)) //nolint:errcheck // drain for keep-alive
		resp.Body.Close()
	}()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		snippet, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return resp.StatusCode, fmt.Errorf("%s %s: %s: %s", method, path, resp.Status, bytes.TrimSpace(snippet))
	}
	if out != nil {
		if err := json.NewDecoder(io.LimitReader(resp.Body, maxRespBytes)).Decode(out); err != nil {
			return resp.StatusCode, fmt.Errorf("decoding response: %w", err)
		}
	}
	return resp.StatusCode, nil
}

// getList GETs a paginated collection, following pages until a short page or the
// page cap. basePath may already carry a query (e.g. "?state=open").
func getList[T any](c *Client, ctx context.Context, basePath string) ([]T, error) {
	sep := "?"
	if strings.Contains(basePath, "?") {
		sep = "&"
	}
	var all []T
	for page := 1; page <= maxPages; page++ {
		var items []T
		p := fmt.Sprintf("%s%spage=%d&per_page=100", basePath, sep, page)
		if err := c.do(ctx, http.MethodGet, p, nil, &items); err != nil {
			return nil, err
		}
		all = append(all, items...)
		if len(items) < 100 {
			break
		}
	}
	return all, nil
}

func seg(s string) string { return url.PathEscape(s) }

type ghUser struct {
	Login string `json:"login"`
	Type  string `json:"type"` // "Bot" for App/Actions identities
}

// CheckRun is a completed check to publish on a commit.
type CheckRun struct {
	Name       string
	HeadSHA    string
	Conclusion string // "success" | "failure" | "neutral" | ...
	Title      string
	Summary    string
}

// CreateCheckRun publishes a completed check run on owner/repo@HeadSHA.
func (c *Client) CreateCheckRun(ctx context.Context, owner, repo string, cr CheckRun) error {
	const maxSummary = 65000 // GitHub caps check output summary at 65535 chars
	summary := cr.Summary
	if len(summary) > maxSummary {
		summary = summary[:maxSummary] + "\n\n_(truncated)_"
	}
	payload := map[string]any{
		"name":       cr.Name,
		"head_sha":   cr.HeadSHA,
		"status":     "completed",
		"conclusion": cr.Conclusion,
		"output":     map[string]string{"title": cr.Title, "summary": summary},
	}
	return c.do(ctx, http.MethodPost,
		fmt.Sprintf("/repos/%s/%s/check-runs", seg(owner), seg(repo)), payload, nil)
}

type issueComment struct {
	ID   int64  `json:"id"`
	Body string `json:"body"`
	User ghUser `json:"user"`
}

// UpsertStickyComment creates or updates a single comment on an issue/PR,
// identified by an HTML-comment marker AND authored by the token's own bot
// identity, so repeated runs edit one comment instead of spamming - and an
// attacker cannot pre-plant a marked comment to hijack the update (author check).
func (c *Client) UpsertStickyComment(ctx context.Context, owner, repo string, issueNumber int, marker, body string) error {
	comments, err := getList[issueComment](c, ctx,
		fmt.Sprintf("/repos/%s/%s/issues/%d/comments", seg(owner), seg(repo), issueNumber))
	if err != nil {
		return err
	}
	full := marker + "\n" + body
	for _, cm := range comments {
		if cm.User.Type == "Bot" && strings.Contains(cm.Body, marker) {
			return c.do(ctx, http.MethodPatch,
				fmt.Sprintf("/repos/%s/%s/issues/comments/%d", seg(owner), seg(repo), cm.ID),
				map[string]string{"body": full}, nil)
		}
	}
	return c.do(ctx, http.MethodPost,
		fmt.Sprintf("/repos/%s/%s/issues/%d/comments", seg(owner), seg(repo), issueNumber),
		map[string]string{"body": full}, nil)
}

type issue struct {
	Number      int              `json:"number"`
	Title       string           `json:"title"`
	Body        string           `json:"body"`
	User        ghUser           `json:"user"`
	PullRequest *json.RawMessage `json:"pull_request"` // present when the entry is a PR
}

// UpsertDashboardIssue creates or updates a single issue (marker + bot author)
// holding the security dashboard, re-asserting the title on update. PRs returned
// by the /issues endpoint are skipped. Returns the issue number.
func (c *Client) UpsertDashboardIssue(ctx context.Context, owner, repo, title, marker, body string) (int, error) {
	issues, err := getList[issue](c, ctx,
		fmt.Sprintf("/repos/%s/%s/issues?state=open", seg(owner), seg(repo)))
	if err != nil {
		return 0, err
	}
	full := marker + "\n" + body
	for _, is := range issues {
		if is.PullRequest != nil { // /issues includes PRs - never treat one as the dashboard
			continue
		}
		if is.User.Type == "Bot" && strings.Contains(is.Body, marker) {
			if err := c.do(ctx, http.MethodPatch,
				fmt.Sprintf("/repos/%s/%s/issues/%d", seg(owner), seg(repo), is.Number),
				map[string]string{"title": title, "body": full}, nil); err != nil {
				return 0, err
			}
			return is.Number, nil
		}
	}
	var created issue
	if err := c.do(ctx, http.MethodPost,
		fmt.Sprintf("/repos/%s/%s/issues", seg(owner), seg(repo)),
		map[string]string{"title": title, "body": full}, &created); err != nil {
		return 0, err
	}
	return created.Number, nil
}

// --- pull-request plumbing (for `egret audit --open-pr`) ---

// escapePath percent-escapes each path segment but preserves the "/" separators,
// as required by the Contents API path.
func escapePath(p string) string {
	parts := strings.Split(strings.TrimPrefix(p, "/"), "/")
	for i := range parts {
		parts[i] = url.PathEscape(parts[i])
	}
	return strings.Join(parts, "/")
}

// GetDefaultBranch returns the repo's default branch.
func (c *Client) GetDefaultBranch(ctx context.Context, owner, repo string) (string, error) {
	var r struct {
		DefaultBranch string `json:"default_branch"`
	}
	if err := c.do(ctx, http.MethodGet, fmt.Sprintf("/repos/%s/%s", seg(owner), seg(repo)), nil, &r); err != nil {
		return "", err
	}
	return r.DefaultBranch, nil
}

func (c *Client) refSHA(ctx context.Context, owner, repo, ref string) (string, error) {
	var r struct {
		Object struct {
			SHA string `json:"sha"`
		} `json:"object"`
	}
	if err := c.do(ctx, http.MethodGet,
		fmt.Sprintf("/repos/%s/%s/git/ref/%s", seg(owner), seg(repo), ref), nil, &r); err != nil {
		return "", err
	}
	return r.Object.SHA, nil
}

// upsertBranch creates refs/heads/branch at sha, or force-updates it if it exists.
func (c *Client) upsertBranch(ctx context.Context, owner, repo, branch, sha string) error {
	code, err := c.status(ctx, http.MethodPost,
		fmt.Sprintf("/repos/%s/%s/git/refs", seg(owner), seg(repo)),
		map[string]string{"ref": "refs/heads/" + branch, "sha": sha}, nil)
	if code == http.StatusUnprocessableEntity { // already exists -> reset it to base
		// The ref in the path keeps its slashes (e.g. heads/egret/update-allowlist).
		return c.do(ctx, http.MethodPatch,
			fmt.Sprintf("/repos/%s/%s/git/refs/%s", seg(owner), seg(repo), escapePath("heads/"+branch)),
			map[string]any{"sha": sha, "force": true}, nil)
	}
	return err
}

// fileSHA returns the blob sha of a file on ref, or ("", false) if it doesn't exist.
func (c *Client) fileSHA(ctx context.Context, owner, repo, path, ref string) (string, bool, error) {
	var r struct {
		SHA string `json:"sha"`
	}
	code, err := c.status(ctx, http.MethodGet,
		fmt.Sprintf("/repos/%s/%s/contents/%s?ref=%s", seg(owner), seg(repo), escapePath(path), url.QueryEscape(ref)),
		nil, &r)
	if code == http.StatusNotFound {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	return r.SHA, true, nil
}

// putFile creates or updates a file on branch (sha required when updating).
func (c *Client) putFile(ctx context.Context, owner, repo, path, branch, message string, content []byte, sha string) error {
	payload := map[string]string{
		"message": message,
		"content": base64.StdEncoding.EncodeToString(content),
		"branch":  branch,
	}
	if sha != "" {
		payload["sha"] = sha
	}
	return c.do(ctx, http.MethodPut,
		fmt.Sprintf("/repos/%s/%s/contents/%s", seg(owner), seg(repo), escapePath(path)), payload, nil)
}

// GetFileContent returns the decoded contents of a file at ref (default branch
// when ref is empty). Used to resolve `extends: org://...` policy references.
func (c *Client) GetFileContent(ctx context.Context, owner, repo, path, ref string) ([]byte, error) {
	q := ""
	if ref != "" {
		q = "?ref=" + url.QueryEscape(ref)
	}
	var r struct {
		Content  string `json:"content"`
		Encoding string `json:"encoding"`
	}
	if err := c.do(ctx, http.MethodGet,
		fmt.Sprintf("/repos/%s/%s/contents/%s%s", seg(owner), seg(repo), escapePath(path), q), nil, &r); err != nil {
		return nil, err
	}
	if r.Encoding != "base64" {
		return nil, fmt.Errorf("unexpected content encoding %q for %s", r.Encoding, path)
	}
	return base64.StdEncoding.DecodeString(strings.ReplaceAll(r.Content, "\n", ""))
}

func (c *Client) findOpenPR(ctx context.Context, owner, repo, head string) (int, error) {
	var prs []struct {
		Number int `json:"number"`
	}
	if err := c.do(ctx, http.MethodGet,
		fmt.Sprintf("/repos/%s/%s/pulls?state=open&head=%s", seg(owner), seg(repo), url.QueryEscape(head)),
		nil, &prs); err != nil {
		return 0, err
	}
	if len(prs) > 0 {
		return prs[0].Number, nil
	}
	return 0, nil
}

// OpenFilePR writes content to path on a dedicated branch and opens (or reuses)
// a pull request into base (default branch if empty). Idempotent: re-running
// updates the branch and the existing PR rather than creating duplicates.
func (c *Client) OpenFilePR(ctx context.Context, owner, repo, path, branch, base, title, body, message string, content []byte) (int, error) {
	if base == "" {
		b, err := c.GetDefaultBranch(ctx, owner, repo)
		if err != nil {
			return 0, err
		}
		base = b
	}
	baseSHA, err := c.refSHA(ctx, owner, repo, "heads/"+base)
	if err != nil {
		return 0, fmt.Errorf("base branch %q: %w", base, err)
	}
	if err := c.upsertBranch(ctx, owner, repo, branch, baseSHA); err != nil {
		return 0, fmt.Errorf("creating branch %q: %w", branch, err)
	}
	sha, _, err := c.fileSHA(ctx, owner, repo, path, branch)
	if err != nil {
		return 0, err
	}
	if err := c.putFile(ctx, owner, repo, path, branch, message, content, sha); err != nil {
		return 0, fmt.Errorf("writing %q: %w", path, err)
	}

	var created struct {
		Number int `json:"number"`
	}
	code, err := c.status(ctx, http.MethodPost,
		fmt.Sprintf("/repos/%s/%s/pulls", seg(owner), seg(repo)),
		map[string]string{"title": title, "head": branch, "base": base, "body": body}, &created)
	if code == http.StatusUnprocessableEntity { // a PR for this head already exists
		return c.findOpenPR(ctx, owner, repo, owner+":"+branch)
	}
	if err != nil {
		return 0, err
	}
	return created.Number, nil
}
