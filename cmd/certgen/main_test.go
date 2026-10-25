package main

import (
	"crypto/tls"
	"crypto/x509"
	"os"
	"path/filepath"
	"testing"
)

func TestGenerateCertificate(t *testing.T) {
	dir := t.TempDir()
	certPath, keyPath := filepath.Join(dir, "certs", "server.crt"), filepath.Join(dir, "keys", "server.key")
	if err := generate(certPath, keyPath, "localhost,127.0.0.1,::1"); err != nil {
		t.Fatal(err)
	}
	pair, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	for _, host := range []string{"localhost", "127.0.0.1", "::1"} {
		if _, err := cert.Verify(x509.VerifyOptions{Roots: pool, DNSName: host}); err != nil {
			t.Fatal(err)
		}
	}
	if err := cert.VerifyHostname("attacker.example"); err == nil {
		t.Fatal("unexpected hostname match")
	}
	info, err := os.Stat(keyPath)
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatalf("key permissions %v %v", info, err)
	}
	if err := generate(certPath, keyPath, "localhost"); err == nil {
		t.Fatal("overwrote existing key")
	}
	newKey := filepath.Join(dir, "new.key")
	if err := generate(certPath, newKey, "localhost"); err == nil {
		t.Fatal("overwrote certificate")
	}
	if _, err := os.Stat(newKey); !os.IsNotExist(err) {
		t.Fatal("partial private key remained")
	}
	if err := generate("same", "same", "localhost"); err == nil {
		t.Fatal("same paths accepted")
	}
	if err := generate(filepath.Join(dir, "other.crt"), filepath.Join(dir, "other.key"), "localhost,"); err == nil {
		t.Fatal("empty hostname accepted")
	}
	blocking := filepath.Join(dir, "file")
	if err := os.WriteFile(blocking, nil, 0600); err != nil {
		t.Fatal(err)
	}
	if err := generate(filepath.Join(blocking, "x.crt"), filepath.Join(dir, "x.key"), "localhost"); err == nil {
		t.Fatal("invalid directory accepted")
	}
}
