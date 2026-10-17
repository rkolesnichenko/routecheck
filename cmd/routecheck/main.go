// Command routecheck checks the routes a BGP neighbour really announces
// against registered RPSL policy: which routes the local AS's import policy
// accepts, rejects or cannot decide, and which the neighbour's own export
// policy does not permit. Run "routecheck -h" for its usage; the logic is in
// internal/cli.
package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/rkolesnichenko/routecheck/internal/cli"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	code := cli.Run(ctx, os.Args[1:], os.Stdout, os.Stderr)
	stop()
	os.Exit(code)
}
