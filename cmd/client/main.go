package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"

	"github.com/ndreuu/go-gophkeeper/internal/cli"
)

var version = "dev"
var buildDate = "unknown"

func main() {
	cli.Version, cli.BuildDate = version, buildDate
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	if err := cli.Run(ctx, os.Args[1:], os.Stdin, os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, "Error:", err)
		os.Exit(1)
	}
}
