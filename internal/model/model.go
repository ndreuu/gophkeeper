package model

import (
	"errors"
	"time"
)

var (
	ErrInvalid      = errors.New("invalid input")
	ErrUnauthorized = errors.New("authentication required")
	ErrNotFound     = errors.New("not found")
	ErrConflict     = errors.New("revision or login conflict")
	ErrCapacity     = errors.New("vault capacity exceeded")
)

const MaxCiphertextSize = 12 * 1024 * 1024

const MaxVaultCiphertextSize = 64 * 1024 * 1024

const MaxVaultRecords = 10000

const MasterVerifierID = "00000000000000000000000000000000"

type Credentials struct {
	Login    string `json:"login"`
	Password string `json:"password"`
}

type User struct {
	ID           string
	Login        string
	PasswordHash string
	VaultSalt    []byte
}

type AuthResult struct {
	Token     string    `json:"token"`
	ExpiresAt time.Time `json:"expires_at"`
	VaultSalt []byte    `json:"vault_salt"`
}

type Record struct {
	ID         string    `json:"id"`
	Revision   int64     `json:"revision"`
	Ciphertext []byte    `json:"ciphertext"`
	UpdatedAt  time.Time `json:"updated_at"`
}

type PutRequest struct {
	ExpectedRevision int64  `json:"expected_revision"`
	Ciphertext       []byte `json:"ciphertext"`
}

type Kind string

const (
	KindLogin  Kind = "login"
	KindText   Kind = "text"
	KindBinary Kind = "binary"
	KindCard   Kind = "card"
)

type LoginData struct {
	Login    string `json:"login"`
	Password string `json:"password"`
}

type BinaryData struct {
	Name string `json:"name"`
	Data []byte `json:"data"`
}

type CardData struct {
	Number string `json:"number"`
	Holder string `json:"holder"`
	Expiry string `json:"expiry"`
	CVV    string `json:"cvv"`
}

type Secret struct {
	Kind     Kind              `json:"kind"`
	Title    string            `json:"title"`
	Metadata map[string]string `json:"metadata,omitempty"`
	Login    *LoginData        `json:"login,omitempty"`
	Text     *string           `json:"text,omitempty"`
	Binary   *BinaryData       `json:"binary,omitempty"`
	Card     *CardData         `json:"card,omitempty"`
}
