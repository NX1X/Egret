package cli

import (
	"fmt"
	"runtime"

	"github.com/spf13/cobra"
)

// Build metadata, overridden at link time:
//
//	go build -ldflags "-X github.com/NX1X/Egret/internal/cli.version=v0.1.0 \
//	  -X github.com/NX1X/Egret/internal/cli.commit=$(git rev-parse --short HEAD)"
var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

func newVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print version, commit, and build info",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			fmt.Fprintf(cmd.OutOrStdout(), "egret %s (commit %s, built %s, %s/%s, %s)\n",
				version, commit, date, runtime.GOOS, runtime.GOARCH, runtime.Version())
			return nil
		},
	}
}
