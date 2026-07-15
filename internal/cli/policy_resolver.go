package cli

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/NX1X/Egret/internal/github"
	"github.com/NX1X/Egret/internal/policy"
)

// orgPolicyResolver resolves `extends: org://owner/repo[/path]` references by
// fetching the file from GitHub with GITHUB_TOKEN. The default path is
// `.egret-policy.yaml`. Local-file extends never reach this resolver.
func orgPolicyResolver() policy.Resolver {
	return func(ref string) ([]byte, error) {
		rest, ok := strings.CutPrefix(ref, "org://")
		if !ok {
			return nil, fmt.Errorf("unsupported extends scheme in %q (only org:// or a file path)", ref)
		}
		parts := strings.SplitN(rest, "/", 3)
		if len(parts) < 2 || parts[0] == "" || parts[1] == "" {
			return nil, fmt.Errorf("bad org ref %q (want org://owner/repo[/path])", ref)
		}
		owner, repo := parts[0], parts[1]
		path := ".egret-policy.yaml"
		if len(parts) == 3 && parts[2] != "" {
			path = parts[2]
		}
		tok := os.Getenv("GITHUB_TOKEN")
		if tok == "" {
			return nil, fmt.Errorf("resolving %q requires GITHUB_TOKEN", ref)
		}
		return github.NewClient(tok).GetFileContent(context.Background(), owner, repo, path, "")
	}
}
