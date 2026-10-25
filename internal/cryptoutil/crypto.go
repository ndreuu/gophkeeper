package cryptoutil

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"unicode/utf8"

	"github.com/ndreuu/go-gophkeeper/internal/model"
	"golang.org/x/crypto/argon2"
)

const (
	keySize      = 32
	saltSize     = 16
	nonceSize    = 12
	tagSize      = 16
	maxTitleSize = 512
)

// NewID returns an unpredictable 128-bit identifier encoded as lowercase hex.
func NewID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate entry ID: %w", err)
	}
	return hex.EncodeToString(b), nil
}

// DeriveKey derives a 32-byte vault key using Argon2id with 64 MiB of memory,
// three iterations and two lanes. The account's random salt must be 16 bytes.
// The caller must retain the salt, never the password or derived key, on disk.
func DeriveKey(password string, salt []byte) ([]byte, error) {
	if len(password) < 8 || len(password) > 1024 || len(salt) != saltSize {
		return nil, fmt.Errorf("derive key: password must contain 8..1024 bytes and salt must contain 16 bytes: %w", model.ErrInvalid)
	}
	return argon2.IDKey([]byte(password), salt, 3, 64*1024, 2, keySize), nil
}

// Encrypt validates and encrypts all of secret using AES-256-GCM. A fresh random
// nonce precedes the ciphertext and tag. The record ID is authenticated as AAD,
// so ciphertext copied to another record cannot be decrypted successfully.
func Encrypt(key []byte, id string, secret model.Secret) ([]byte, error) {
	if err := Validate(secret); err != nil {
		return nil, err
	}
	aead, err := newAEAD(key, id)
	if err != nil {
		return nil, err
	}
	plaintext, err := json.Marshal(secret)
	if err != nil {
		return nil, fmt.Errorf("encode secret: %w", err)
	}
	defer clear(plaintext)
	if len(plaintext) > model.MaxCiphertextSize-aead.NonceSize()-aead.Overhead() {
		return nil, fmt.Errorf("secret is too large: %w", model.ErrInvalid)
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("generate encryption nonce: %w", err)
	}
	return aead.Seal(nonce, nonce, plaintext, []byte(id)), nil
}

// Decrypt authenticates ciphertext and its record ID, then decodes and validates
// the secret. A wrong key, modified ciphertext or wrong ID returns an error and
// never exposes unauthenticated plaintext.
func Decrypt(key []byte, id string, ciphertext []byte) (model.Secret, error) {
	aead, err := newAEAD(key, id)
	if err != nil {
		return model.Secret{}, err
	}
	if len(ciphertext) < aead.NonceSize()+aead.Overhead() || len(ciphertext) > model.MaxCiphertextSize {
		return model.Secret{}, fmt.Errorf("invalid encrypted entry size: %w", model.ErrInvalid)
	}
	nonce := ciphertext[:aead.NonceSize()]
	plaintext, err := aead.Open(nil, nonce, ciphertext[aead.NonceSize():], []byte(id))
	if err != nil {
		return model.Secret{}, fmt.Errorf("cannot decrypt entry: incorrect password or damaged data: %w", model.ErrInvalid)
	}
	defer clear(plaintext)
	var secret model.Secret
	if err := json.Unmarshal(plaintext, &secret); err != nil {
		return model.Secret{}, fmt.Errorf("decode encrypted entry: %w", model.ErrInvalid)
	}
	if err := Validate(secret); err != nil {
		return model.Secret{}, err
	}
	return secret, nil
}

// Validate checks the typed payload and UTF-8 text without imposing provider
// rules on private data. Exactly one payload must match Kind; empty text and
// empty binary files are valid. Titles may contain at most 512 bytes.
func Validate(secret model.Secret) error {
	invalid := func(reason string) error { return fmt.Errorf("%s: %w", reason, model.ErrInvalid) }
	if strings.TrimSpace(secret.Title) == "" || len(secret.Title) > maxTitleSize || !utf8.ValidString(secret.Title) {
		return invalid("entry title must contain 1..512 bytes of UTF-8 text")
	}
	for k, v := range secret.Metadata {
		if !utf8.ValidString(k) || !utf8.ValidString(v) {
			return invalid("metadata must contain valid UTF-8 text")
		}
	}
	payloads := 0
	for _, present := range []bool{secret.Login != nil, secret.Text != nil, secret.Binary != nil, secret.Card != nil} {
		if present {
			payloads++
		}
	}
	if payloads != 1 {
		return invalid("exactly one payload is required")
	}
	switch secret.Kind {
	case model.KindLogin:
		if secret.Login == nil || secret.Login.Login == "" || secret.Login.Password == "" {
			return invalid("login entry requires a login and password")
		}
		if !utf8.ValidString(secret.Login.Login) || !utf8.ValidString(secret.Login.Password) {
			return invalid("login fields must contain valid UTF-8 text")
		}
	case model.KindText:
		if secret.Text == nil || !utf8.ValidString(*secret.Text) {
			return invalid("text entry requires UTF-8 text")
		}
	case model.KindBinary:
		if secret.Binary == nil || !utf8.ValidString(secret.Binary.Name) {
			return invalid("binary entry requires a file payload with a UTF-8 name")
		}
		if len(secret.Binary.Data) > model.MaxCiphertextSize-nonceSize-tagSize {
			return invalid("binary entry is too large")
		}
	case model.KindCard:
		if secret.Card == nil {
			return invalid("card entry requires card data")
		}
		for _, v := range []string{secret.Card.Number, secret.Card.Holder, secret.Card.Expiry, secret.Card.CVV} {
			if strings.TrimSpace(v) == "" || !utf8.ValidString(v) {
				return invalid("card fields must contain nonempty UTF-8 text")
			}
		}
	default:
		return invalid("unsupported entry kind")
	}
	return nil
}

func newAEAD(key []byte, id string) (cipher.AEAD, error) {
	if len(key) != keySize || !validID(id) {
		return nil, fmt.Errorf("a 32-byte key and a 32-character lowercase hex ID are required: %w", model.ErrInvalid)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("initialize encryption: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("initialize GCM: %w", err)
	}
	return aead, nil
}

func validID(id string) bool {
	if len(id) != 32 {
		return false
	}
	for _, c := range id {
		if c < '0' || c > '9' {
			if c < 'a' || c > 'f' {
				return false
			}
		}
	}
	return true
}
