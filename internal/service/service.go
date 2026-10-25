package service

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math"
	"time"

	"github.com/ndreuu/go-gophkeeper/internal/model"
)

type Store interface {
	CreateUser(context.Context, model.User) error
	FindUser(context.Context, string) (model.User, error)
	CreateSession(context.Context, []byte, string, time.Time) error
	SessionUser(context.Context, []byte, time.Time) (string, error)
	DeleteSession(context.Context, []byte) error
	ListRecords(context.Context, string) ([]model.Record, error)
	GetRecord(context.Context, string, string) (model.Record, error)
	PutRecord(context.Context, string, string, int64, []byte) (model.Record, error)
	DeleteRecord(context.Context, string, string, int64) error
}

type Service struct {
	store         Store
	sessionTTL    time.Duration
	now           func() time.Time
	random        io.Reader
	passwordSlots chan struct{}
}

// New constructs a service; a nonpositive session TTL selects 24 hours.
func New(store Store, sessionTTL time.Duration) *Service {
	if sessionTTL <= 0 {
		sessionTTL = 24 * time.Hour
	}
	return &Service{store: store, sessionTTL: sessionTTL, now: time.Now, random: rand.Reader,
		passwordSlots: make(chan struct{}, 4)}
}

// Register creates an account with an independent public vault salt and starts a session.
func (s *Service) Register(ctx context.Context, credentials model.Credentials) (model.AuthResult, error) {
	if err := validateCredentials(credentials); err != nil {
		return model.AuthResult{}, err
	}
	id, err := s.randomBytes(16)
	if err != nil {
		return model.AuthResult{}, err
	}
	vaultSalt, err := s.randomBytes(16)
	if err != nil {
		return model.AuthResult{}, err
	}
	hashSalt, err := s.randomBytes(16)
	if err != nil {
		return model.AuthResult{}, err
	}
	hash, err := s.derivePasswordHash(ctx, credentials.Password, hashSalt)
	if err != nil {
		return model.AuthResult{}, err
	}
	user := model.User{ID: hex.EncodeToString(id), Login: credentials.Login,
		PasswordHash: hash, VaultSalt: vaultSalt}
	if err := s.store.CreateUser(ctx, user); err != nil {
		return model.AuthResult{}, fmt.Errorf("create account: %w", err)
	}
	return s.startSession(ctx, user)
}

// Login verifies the password in constant time and issues an opaque random bearer token.
func (s *Service) Login(ctx context.Context, credentials model.Credentials) (model.AuthResult, error) {
	if err := validateCredentials(credentials); err != nil {
		return model.AuthResult{}, err
	}
	user, err := s.store.FindUser(ctx, credentials.Login)
	if err != nil {
		if errors.Is(err, model.ErrNotFound) {
			if _, err := s.derivePasswordHash(ctx, credentials.Password, make([]byte, 16)); err != nil {
				return model.AuthResult{}, err
			}
			return model.AuthResult{}, model.ErrUnauthorized
		}
		return model.AuthResult{}, fmt.Errorf("find account: %w", err)
	}
	valid, err := s.verifyAccountPassword(ctx, credentials.Password, user.PasswordHash)
	if err != nil {
		return model.AuthResult{}, err
	}
	if !valid {
		return model.AuthResult{}, model.ErrUnauthorized
	}
	return s.startSession(ctx, user)
}

func (s *Service) acquirePasswordSlot(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	select {
	case s.passwordSlots <- struct{}{}:
		if err := ctx.Err(); err != nil {
			<-s.passwordSlots
			return err
		}
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (s *Service) derivePasswordHash(ctx context.Context, password string, salt []byte) (string, error) {
	if err := s.acquirePasswordSlot(ctx); err != nil {
		return "", err
	}
	defer func() { <-s.passwordSlots }()
	return hashPassword(password, salt), nil
}

func (s *Service) verifyAccountPassword(ctx context.Context, password, encoded string) (bool, error) {
	if err := s.acquirePasswordSlot(ctx); err != nil {
		return false, err
	}
	defer func() { <-s.passwordSlots }()
	return verifyPassword(password, encoded), nil
}

func (s *Service) startSession(ctx context.Context, user model.User) (model.AuthResult, error) {
	random, err := s.randomBytes(32)
	if err != nil {
		return model.AuthResult{}, err
	}
	token := base64.RawURLEncoding.EncodeToString(random)
	tokenHash := sha256.Sum256([]byte(token))
	expires := s.now().UTC().Add(s.sessionTTL)
	if err := s.store.CreateSession(ctx, tokenHash[:], user.ID, expires); err != nil {
		return model.AuthResult{}, fmt.Errorf("create session: %w", err)
	}
	return model.AuthResult{Token: token, ExpiresAt: expires, VaultSalt: user.VaultSalt}, nil
}

// Authenticate resolves an unexpired bearer session without persisting the token itself.
func (s *Service) Authenticate(ctx context.Context, token string) (string, error) {
	hash, err := parseToken(token)
	if err != nil {
		return "", err
	}
	userID, err := s.store.SessionUser(ctx, hash, s.now().UTC())
	if errors.Is(err, model.ErrNotFound) {
		return "", model.ErrUnauthorized
	}
	if err != nil {
		return "", fmt.Errorf("authenticate session: %w", err)
	}
	return userID, nil
}

// Logout revokes a bearer token; repeating a successful revocation is harmless.
func (s *Service) Logout(ctx context.Context, token string) error {
	hash, err := parseToken(token)
	if err != nil {
		return err
	}
	return s.store.DeleteSession(ctx, hash)
}

// List returns the owner's complete encrypted snapshot, including an empty JSON array.
func (s *Service) List(ctx context.Context, userID string) ([]model.Record, error) {
	if err := validateOwner(userID); err != nil {
		return nil, err
	}
	records, err := s.store.ListRecords(ctx, userID)
	if err != nil {
		return nil, err
	}
	if records == nil {
		records = []model.Record{}
	}
	return records, nil
}

// Get reads an encrypted entry belonging to the authenticated owner.
func (s *Service) Get(ctx context.Context, userID, id string) (model.Record, error) {
	if err := validateRecordIdentity(userID, id); err != nil {
		return model.Record{}, err
	}
	return s.store.GetRecord(ctx, userID, id)
}

// Put creates or atomically updates an encrypted entry at the expected revision.
func (s *Service) Put(ctx context.Context, userID, id string, request model.PutRequest) (model.Record, error) {
	if err := validateRecordIdentity(userID, id); err != nil {
		return model.Record{}, err
	}
	if request.ExpectedRevision < 0 || request.ExpectedRevision == math.MaxInt64 {
		return model.Record{}, fmt.Errorf("%w: invalid expected revision", model.ErrInvalid)
	}
	if id == model.MasterVerifierID && request.ExpectedRevision != 0 {
		return model.Record{}, fmt.Errorf("%w: master verifier cannot be replaced", model.ErrInvalid)
	}
	if len(request.Ciphertext) < 28 || len(request.Ciphertext) > model.MaxCiphertextSize {
		return model.Record{}, fmt.Errorf("%w: invalid encrypted entry size", model.ErrInvalid)
	}
	return s.store.PutRecord(ctx, userID, id, request.ExpectedRevision, request.Ciphertext)
}

// Delete removes an owner's entry only if its revision still matches.
func (s *Service) Delete(ctx context.Context, userID, id string, revision int64) error {
	if err := validateRecordIdentity(userID, id); err != nil {
		return err
	}
	if id == model.MasterVerifierID {
		return fmt.Errorf("%w: master verifier cannot be deleted", model.ErrInvalid)
	}
	if revision <= 0 {
		return fmt.Errorf("%w: positive revision required", model.ErrInvalid)
	}
	return s.store.DeleteRecord(ctx, userID, id, revision)
}

func (s *Service) randomBytes(size int) ([]byte, error) {
	value := make([]byte, size)
	if _, err := io.ReadFull(s.random, value); err != nil {
		return nil, fmt.Errorf("generate secure randomness: %w", err)
	}
	return value, nil
}

func parseToken(token string) ([]byte, error) {
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(token)
	if err != nil || len(decoded) != 32 || len(token) != 43 {
		return nil, model.ErrUnauthorized
	}
	hash := sha256.Sum256([]byte(token))
	return hash[:], nil
}

func validateCredentials(credentials model.Credentials) error {
	if len(credentials.Login) < 3 || len(credentials.Login) > 64 || len(credentials.Password) < 8 || len(credentials.Password) > 1024 {
		return fmt.Errorf("%w: login must contain 3..64 characters and password 8..1024 bytes", model.ErrInvalid)
	}
	for _, character := range credentials.Login {
		if character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' || character >= '0' && character <= '9' || character == '_' || character == '.' || character == '-' {
			continue
		}
		return fmt.Errorf("%w: unsupported login character", model.ErrInvalid)
	}
	return nil
}

func validID(id string) bool {
	if len(id) != 32 {
		return false
	}
	for _, character := range id {
		if character >= '0' && character <= '9' || character >= 'a' && character <= 'f' {
			continue
		}
		return false
	}
	return true
}

func validateOwner(id string) error {
	if !validID(id) {
		return model.ErrUnauthorized
	}
	return nil
}

func validateRecordIdentity(userID, id string) error {
	if err := validateOwner(userID); err != nil {
		return err
	}
	if !validID(id) {
		return fmt.Errorf("%w: entry ID must contain 32 lowercase hexadecimal characters", model.ErrInvalid)
	}
	return nil
}
