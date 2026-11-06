// Command prolexic is a CLI for Akamai Prolexic, over the Akamai APIs.
package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/dvmrry/akamai-prolexic/internal/cli"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	code := cli.Run(ctx, os.Args[1:], cli.OSEnv())
	stop()
	os.Exit(code)
}
