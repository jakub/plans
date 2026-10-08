// Command plans provides the artifact publishing CLI.
package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/jakub/plans/internal/cli"
)

func main() {
	os.Exit(run())
}

func run() int {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	return cli.Run(ctx, os.Args[1:], cli.Streams{}, cli.Dependencies{})
}
