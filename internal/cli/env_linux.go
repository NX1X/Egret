//go:build linux

package cli

import (
	"os"
	"strings"
)

// secretEnvPrefixes are the environment variables Egret itself uses to carry
// CALLER credentials. They must never reach the wrapped build.
//
// The build is the third-party toolchain and dependency code Egret exists to
// watch, and it is started from this process's environment - so without filtering
// it inherits every secret the action was configured with. The Action entrypoint
// already drops EGRET_GITHUB_TOKEN before exec'ing the binary; doing it here as
// well covers a direct `egret run` invocation, which the entrypoint never sees.
//
// EGRET_INGEST_TOKEN is the more serious of the two: it authenticates report
// submission to the self-hosted dashboard, so a hostile dependency that reads it
// can forge or suppress the very findings that were supposed to catch it. Egret
// reads it from its OWN environment (see executeRun), which is left untouched, so
// removing it from the child changes no behaviour.
var secretEnvPrefixes = []string{
	"EGRET_INGEST_TOKEN=",
	"EGRET_GITHUB_TOKEN=",
}

// sanitizedEnviron returns os.Environ() with Egret's own credential variables
// removed. Use it anywhere an environment is handed to the wrapped build; there
// must be no other path that forwards os.Environ() to a child.
func sanitizedEnviron() []string {
	src := os.Environ()
	out := make([]string, 0, len(src))
	for _, kv := range src {
		if isSecretEnv(kv) {
			continue
		}
		out = append(out, kv)
	}
	return out
}

// isSecretEnv reports whether a "KEY=value" entry names one of Egret's own
// credential variables.
func isSecretEnv(kv string) bool {
	for _, p := range secretEnvPrefixes {
		if strings.HasPrefix(kv, p) {
			return true
		}
	}
	return false
}
