package main

import (
	"context"
	"flag"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/patrickpichler/ebpf-ja4plus-fingerprinting/pkg/tracer"
)

func main() {
	log := slog.New(slog.NewTextHandler(os.Stdout,
		&slog.HandlerOptions{
			Level: slog.LevelDebug,
		}))

	flag.Parse()

	tracer, err := tracer.New(log, tracer.TracerCfg{})
	if err != nil {
		log.Error("error while creating tracer",
			slog.Any("error", err))
		os.Exit(1)
	}

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGTERM)
	defer cancel()

	if err := tracer.Init(); err != nil {
		log.Error("error while initializing tracer",
			slog.Any("error", err))
		os.Exit(1)
	}

	done := make(chan error)
	go func() {
		done <- tracer.Run(ctx)
	}()

	err = <-done
	if err != nil {
		log.Error("error while shutting down tracer",
			slog.Any("error", err))
		os.Exit(1)
	}
}
