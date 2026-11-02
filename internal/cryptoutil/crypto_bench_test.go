package cryptoutil

import (
	"bytes"
	"testing"

	"github.com/ndreuu/go-gophkeeper/internal/model"
)

func BenchmarkDeriveKey(b *testing.B) {
	password := "correct horse battery staple"
	salt := []byte("0123456789abcdef")
	b.ReportAllocs()
	for b.Loop() {
		if _, err := DeriveKey(password, salt); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkEncrypt(b *testing.B) {
	for _, tc := range []struct {
		name string
		size int
	}{
		{"1KiB", 1024},
		{"1MiB", 1024 * 1024},
	} {
		b.Run(tc.name, func(b *testing.B) {
			key := bytes.Repeat([]byte{42}, keySize)
			secret := benchmarkSecret(tc.size)
			b.ReportAllocs()
			b.SetBytes(int64(tc.size))
			for b.Loop() {
				if _, err := Encrypt(key, testID, secret); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkDecrypt(b *testing.B) {
	for _, tc := range []struct {
		name string
		size int
	}{
		{"1KiB", 1024},
		{"1MiB", 1024 * 1024},
	} {
		b.Run(tc.name, func(b *testing.B) {
			key := bytes.Repeat([]byte{42}, keySize)
			secret := benchmarkSecret(tc.size)
			ciphertext, err := Encrypt(key, testID, secret)
			if err != nil {
				b.Fatal(err)
			}
			b.ReportAllocs()
			b.SetBytes(int64(tc.size))
			for b.Loop() {
				if _, err := Decrypt(key, testID, ciphertext); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func benchmarkSecret(size int) model.Secret {
	return model.Secret{
		Kind:     model.KindBinary,
		Title:    "file",
		Metadata: map[string]string{"purpose": "benchmark"},
		Binary:   &model.BinaryData{Name: "file.bin", Data: bytes.Repeat([]byte{42}, size)},
	}
}
