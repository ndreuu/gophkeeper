package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func main() {
	cert := flag.String("cert", "certs/server.crt", "certificate output path")
	key := flag.String("key", "certs/server.key", "private key output path")
	hosts := flag.String("hosts", "localhost,127.0.0.1,::1", "comma-separated certificate DNS names and IPs")
	flag.Parse()
	if err := generate(*cert, *key, *hosts); err != nil {
		fmt.Fprintln(os.Stderr, "certgen:", err)
		os.Exit(1)
	}
	fmt.Println("Certificate:", *cert)
}

func generate(certPath, keyPath, hosts string) error {
	if filepath.Clean(certPath) == filepath.Clean(keyPath) {
		return fmt.Errorf("certificate and private key paths must differ")
	}
	private, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return err
	}
	now := time.Now()
	template := x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: "GophKeeper development"}, NotBefore: now.Add(-time.Minute), NotAfter: now.AddDate(1, 0, 0), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, BasicConstraintsValid: true}
	for _, host := range strings.Split(hosts, ",") {
		host = strings.TrimSpace(host)
		if host == "" {
			return fmt.Errorf("certificate hosts cannot be empty")
		}
		if ip := net.ParseIP(host); ip != nil {
			template.IPAddresses = append(template.IPAddresses, ip)
		} else {
			template.DNSNames = append(template.DNSNames, host)
		}
	}
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &private.PublicKey, private)
	if err != nil {
		return err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(private)
	if err != nil {
		return err
	}
	for _, name := range []string{certPath, keyPath} {
		if err = os.MkdirAll(filepath.Dir(name), 0700); err != nil {
			return err
		}
	}
	keyFile, err := os.OpenFile(keyPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	keepKey := false
	defer func() {
		_ = keyFile.Close()
		if !keepKey {
			_ = os.Remove(keyPath)
		}
	}()
	if err = pem.Encode(keyFile, &pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}); err != nil {
		return err
	}
	if err = keyFile.Close(); err != nil {
		return err
	}
	certFile, err := os.OpenFile(certPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	if err = pem.Encode(certFile, &pem.Block{Type: "CERTIFICATE", Bytes: der}); err != nil {
		_ = certFile.Close()
		_ = os.Remove(certPath)
		return err
	}
	if err = certFile.Close(); err != nil {
		_ = os.Remove(certPath)
		return err
	}
	keepKey = true
	return nil
}
