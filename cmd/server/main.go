package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/ndreuu/go-gophkeeper/internal/config"
	"github.com/ndreuu/go-gophkeeper/internal/handler"
	"github.com/ndreuu/go-gophkeeper/internal/logger"
	"github.com/ndreuu/go-gophkeeper/internal/repository"
	"github.com/ndreuu/go-gophkeeper/internal/service"
	"go.uber.org/zap"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "server:", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, args []string, out io.Writer) error {
	cfg, err := config.Load(args, os.Getenv)
	if errors.Is(err, flag.ErrHelp) {
		_, err = io.WriteString(out, config.Usage)
		return err
	}
	if err != nil {
		return err
	}
	log, err := logger.New(cfg.LogLevel)
	if err != nil {
		return err
	}
	defer func() { _ = log.Sync() }()
	cert, err := tls.LoadX509KeyPair(cfg.TLSCert, cfg.TLSKey)
	if err != nil {
		return fmt.Errorf("load TLS certificate: %w", err)
	}
	startup, cancel := context.WithTimeout(ctx, 15*time.Second)
	store, err := repository.New(startup, cfg.DatabaseDSN)
	cancel()
	if err != nil {
		return fmt.Errorf("initialize storage: %w", err)
	}
	defer store.Close()
	srv := &http.Server{Addr: cfg.Address, Handler: handler.New(service.New(store, cfg.SessionTTL), store.Ping, log), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 30 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 16 * 1024, TLSConfig: &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{cert}}}
	log.Info("starting HTTPS server", zap.String("address", cfg.Address))
	return serve(ctx, srv)
}

func serve(ctx context.Context, srv *http.Server) error {
	listener, err := net.Listen("tcp", srv.Addr)
	if err != nil {
		return fmt.Errorf("listen: %w", err)
	}
	finished := make(chan error, 1)
	go func() { finished <- srv.Serve(tls.NewListener(listener, srv.TLSConfig)) }()
	select {
	case err = <-finished:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	case <-ctx.Done():
		shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err = srv.Shutdown(shutdown); err != nil {
			_ = srv.Close()
			<-finished
			return fmt.Errorf("shutdown: %w", err)
		}
		<-finished
		return nil
	}
}
