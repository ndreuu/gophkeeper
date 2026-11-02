package cryptoutil

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/hex"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/ndreuu/go-gophkeeper/internal/model"
)

const testID = "0123456789abcdef0123456789abcdef"

func TestNewID(t *testing.T) {
	seen := map[string]bool{}
	for range 32 {
		id, err := NewID()
		if err != nil {
			t.Fatal(err)
		}
		if !model.ValidID(id) || seen[id] {
			t.Fatalf("invalid or repeated ID: %q", id)
		}
		seen[id] = true
	}
}

func TestDeriveKey(t *testing.T) {
	salt := []byte("0123456789abcdef")
	key, err := DeriveKey("correct horse battery staple", salt)
	if err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(key); got != "52a72337c144851f42dda54f01e3dbc218e56b0aba9aa28618e1426c81bb8bc5" {
		t.Fatalf("derived key: %s", got)
	}
	otherPassword, err := DeriveKey("another correct password", salt)
	if err != nil {
		t.Fatal(err)
	}
	otherSalt, err := DeriveKey("correct horse battery staple", []byte("fedcba9876543210"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(key, otherPassword) || bytes.Equal(key, otherSalt) {
		t.Fatal("vault key does not depend on both password and account salt")
	}
	if _, err := DeriveKey("short", salt); !errors.Is(err, model.ErrInvalid) {
		t.Fatalf("short password: %v", err)
	}
	if _, err := DeriveKey(strings.Repeat("p", 1025), salt); !errors.Is(err, model.ErrInvalid) {
		t.Fatalf("long password: %v", err)
	}
	if _, err := DeriveKey("password", salt[:15]); !errors.Is(err, model.ErrInvalid) {
		t.Fatalf("short salt: %v", err)
	}
}

func TestEncryptDecryptAllKinds(t *testing.T) {
	text := "private note — 東京"
	secrets := []model.Secret{
		{Kind: model.KindLogin, Title: "account", Metadata: map[string]string{"site": "https://example.test", "OTP": "secret OTP"}, Login: &model.LoginData{Login: "alice", Password: "top secret password"}},
		{Kind: model.KindText, Title: "note", Text: &text},
		{Kind: model.KindBinary, Title: "file", Binary: &model.BinaryData{Name: "résumé.bin", Data: []byte{0, 1, 255, 0}}},
		{Kind: model.KindCard, Title: "card", Card: &model.CardData{Number: "1234 5678 9012 3456", Holder: "Alice", Expiry: "01/30", CVV: "123"}},
	}
	key := bytes.Repeat([]byte{42}, 32)
	for _, secret := range secrets {
		t.Run(string(secret.Kind), func(t *testing.T) {
			first, err := Encrypt(key, testID, secret)
			if err != nil {
				t.Fatal(err)
			}
			second, err := Encrypt(key, testID, secret)
			if err != nil {
				t.Fatal(err)
			}
			if bytes.Equal(first, second) {
				t.Fatal("nonce reuse: repeated encryption was identical")
			}
			if bytes.Contains(first, []byte(secret.Title)) {
				t.Fatal("title leaked into ciphertext")
			}
			got, err := Decrypt(key, testID, first)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(got, secret) {
				t.Fatalf("round trip mismatch: %#v", got)
			}
		})
	}
}

func TestDecryptRejectsTampering(t *testing.T) {
	text := "secret"
	key := bytes.Repeat([]byte{1}, 32)
	encrypted, err := Encrypt(key, testID, model.Secret{Kind: model.KindText, Title: "title", Text: &text})
	if err != nil {
		t.Fatal(err)
	}
	for _, index := range []int{0, nonceSize, len(encrypted) - 1} {
		damaged := bytes.Clone(encrypted)
		damaged[index] ^= 1
		if got, err := Decrypt(key, testID, damaged); !errors.Is(err, model.ErrInvalid) || got.Kind != "" {
			t.Fatalf("damaged byte %d exposed data: %#v %v", index, got, err)
		}
	}
	if _, err := Decrypt(bytes.Repeat([]byte{2}, 32), testID, encrypted); !errors.Is(err, model.ErrInvalid) {
		t.Fatalf("wrong key: %v", err)
	}
	if _, err := Decrypt(key, strings.Repeat("a", 32), encrypted); !errors.Is(err, model.ErrInvalid) {
		t.Fatalf("wrong record ID: %v", err)
	}
}

func TestEncryptDecryptInvalidInputs(t *testing.T) {
	text := "secret"
	secret := model.Secret{Kind: model.KindText, Title: "note", Text: &text}
	key := bytes.Repeat([]byte{1}, 32)
	for _, tc := range []struct {
		key []byte
		id  string
	}{
		{key[:16], testID}, {key, "invalid"}, {key, strings.Repeat("A", 32)}, {key, strings.Repeat("g", 32)},
	} {
		if _, err := Encrypt(tc.key, tc.id, secret); !errors.Is(err, model.ErrInvalid) {
			t.Fatalf("encrypt invalid input: %v", err)
		}
		if _, err := Decrypt(tc.key, tc.id, []byte("bad")); !errors.Is(err, model.ErrInvalid) {
			t.Fatalf("decrypt invalid input: %v", err)
		}
	}
	if _, err := Encrypt(key, testID, model.Secret{}); !errors.Is(err, model.ErrInvalid) {
		t.Fatalf("invalid secret: %v", err)
	}
	for _, data := range [][]byte{nil, make([]byte, 27), make([]byte, model.MaxCiphertextSize+1)} {
		if _, err := Decrypt(key, testID, data); !errors.Is(err, model.ErrInvalid) {
			t.Fatalf("invalid encrypted size: %v", err)
		}
	}
	large := strings.Repeat("a", model.MaxCiphertextSize)
	if _, err := Encrypt(key, testID, model.Secret{Kind: model.KindText, Title: "large", Text: &large}); !errors.Is(err, model.ErrInvalid) {
		t.Fatalf("oversized plaintext: %v", err)
	}
}

func TestDecryptRejectsMalformedAuthenticatedPayload(t *testing.T) {
	key := bytes.Repeat([]byte{1}, 32)
	block, _ := aes.NewCipher(key)
	aead, _ := cipher.NewGCM(block)
	for _, plaintext := range []string{"not JSON", `{"kind":"text","title":"missing payload"}`} {
		nonce := make([]byte, aead.NonceSize())
		data := aead.Seal(nonce, nonce, []byte(plaintext), []byte(testID))
		if _, err := Decrypt(key, testID, data); !errors.Is(err, model.ErrInvalid) {
			t.Fatalf("invalid authenticated payload: %v", err)
		}
	}
}

func TestValidate(t *testing.T) {
	empty := ""
	valid := []model.Secret{
		{Kind: model.KindText, Title: "empty text", Text: &empty},
		{Kind: model.KindBinary, Title: "empty file", Binary: &model.BinaryData{}},
	}
	for _, secret := range valid {
		if err := Validate(secret); err != nil {
			t.Fatal(err)
		}
	}
	badUTF8 := string([]byte{0xff})
	invalid := []model.Secret{
		{},
		{Kind: model.KindText, Title: " ", Text: &empty},
		{Kind: model.KindText, Title: strings.Repeat("x", 513), Text: &empty},
		{Kind: model.KindText, Title: badUTF8, Text: &empty},
		{Kind: model.KindText, Title: "title", Metadata: map[string]string{badUTF8: "value"}, Text: &empty},
		{Kind: model.KindText, Title: "title", Metadata: map[string]string{"key": badUTF8}, Text: &empty},
		{Kind: model.KindText, Title: "title"},
		{Kind: model.KindText, Title: "title", Text: &empty, Login: &model.LoginData{}},
		{Kind: model.KindLogin, Title: "title", Text: &empty},
		{Kind: model.KindLogin, Title: "title", Login: &model.LoginData{Login: "alice"}},
		{Kind: model.KindLogin, Title: "title", Login: &model.LoginData{Login: "alice", Password: badUTF8}},
		{Kind: model.KindText, Title: "title", Binary: &model.BinaryData{}},
		{Kind: model.KindText, Title: "title", Text: &badUTF8},
		{Kind: model.KindBinary, Title: "title", Text: &empty},
		{Kind: model.KindBinary, Title: "title", Binary: &model.BinaryData{Name: badUTF8}},
		{Kind: model.KindBinary, Title: "title", Binary: &model.BinaryData{Data: make([]byte, model.MaxCiphertextSize)}},
		{Kind: model.KindCard, Title: "title", Text: &empty},
		{Kind: model.KindCard, Title: "title", Card: &model.CardData{}},
		{Kind: "unknown", Title: "title", Text: &empty},
	}
	for i, secret := range invalid {
		if err := Validate(secret); !errors.Is(err, model.ErrInvalid) {
			t.Errorf("case %d: %v", i, err)
		}
	}
}
