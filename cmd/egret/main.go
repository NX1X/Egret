// Command egret is the Egret runtime security agent CLI.
//
// Egret wraps a build/command, monitors its network egress, processes, and
// file writes via eBPF, and (in block mode) enforces a domain allowlist.
//
//	sudo egret run --config policy.yaml -- ./build.sh
package main

import (
	"os"

	"github.com/NX1X/Egret/internal/cli"
)

func main() {
	os.Exit(cli.Execute())
}
