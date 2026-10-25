package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestRunHelpAndErrors(t *testing.T) {
	var out bytes.Buffer
	if err := run(context.Background(), []string{"-h"}, &out); err != nil || !strings.Contains(out.String(), "database-dsn") {
		t.Fatalf("help %q %v", out.String(), err)
	}
	if err := run(context.Background(), []string{"-unknown"}, &out); err == nil {
		t.Fatal("invalid arguments accepted")
	}
	if err := run(context.Background(), []string{"-d", "unused", "-tls-cert", "/missing.crt", "-tls-key", "/missing.key"}, &out); err == nil {
		t.Fatal("missing certificate accepted")
	}
}

func TestServeTLSAndGracefulShutdown(t *testing.T) {
	seed := httptest.NewTLSServer(http.NotFoundHandler())
	pair := seed.TLS.Certificates[0]
	cert := seed.Certificate()
	seed.Close()
	roots := x509.NewCertPool()
	roots.AddCert(cert)
	transport := &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 5 * time.Second}
	started, release := make(chan struct{}), make(chan struct{})
	address := make(chan string, 1)
	srv := &http.Server{Addr: "127.0.0.1:0", TLSConfig: &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{pair}}, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(started)
		<-release
		w.WriteHeader(http.StatusNoContent)
	}), BaseContext: func(listener net.Listener) context.Context {
		address <- listener.Addr().String()
		return context.Background()
	}}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- serve(ctx, srv) }()
	var addr string
	select {
	case addr = <-address:
	case err := <-done:
		t.Fatalf("start: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("server did not start")
	}
	response := make(chan error, 1)
	go func() {
		resp, err := client.Get("https://" + addr)
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode != http.StatusNoContent {
				err = errors.New("unexpected response")
			}
		}
		response <- err
	}()
	select {
	case <-started:
	case err := <-response:
		t.Fatalf("TLS request failed: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("TLS request timed out")
	}
	cancel()
	select {
	case err := <-done:
		t.Fatalf("shutdown interrupted active request: %v", err)
	default:
	}
	close(release)
	if err := <-response; err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("shutdown timed out")
	}
}

func TestServeListenError(t *testing.T) {
	err := serve(context.Background(), &http.Server{Addr: "invalid address"})
	if err == nil || !strings.Contains(err.Error(), "listen") {
		t.Fatalf("listen error: %v", err)
	}
}
