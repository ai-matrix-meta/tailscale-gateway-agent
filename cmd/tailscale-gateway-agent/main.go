package main

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/ai-matrix-meta/tailscale-gateway-agent/internal/bootstrap"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := bootstrap.Run(ctx, os.Args[1:]); err != nil {
		slog.Error("tailscale gateway agent stopped", "error", err)
		os.Exit(1)
	}
}
