package repository

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/ndreuu/go-gophkeeper/internal/model"
)

func TestPostgresIntegration(t *testing.T) {
	dsn := os.Getenv("GOPHKEEPER_TEST_DATABASE_DSN")
	if dsn == "" {
		t.Skip("GOPHKEEPER_TEST_DATABASE_DSN is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	store, err := New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	id := func() string {
		value := make([]byte, 16)
		if _, err := rand.Read(value); err != nil {
			t.Fatal(err)
		}
		return hex.EncodeToString(value)
	}
	owner, other, entry := id(), id(), id()
	for _, userID := range []string{owner, other} {
		if err := store.CreateUser(ctx, model.User{ID: userID, Login: "test_" + userID,
			PasswordHash: "test-only-hash", VaultSalt: make([]byte, 16)}); err != nil {
			t.Fatal(err)
		}
		defer func(owner string) {
			if _, err := store.db.ExecContext(context.Background(), "DELETE FROM users WHERE id = $1", owner); err != nil {
				t.Error(err)
			}
		}(userID)
	}
	if err := store.CreateUser(ctx, model.User{ID: id(), Login: "test_" + owner,
		PasswordHash: "test-only-hash", VaultSalt: make([]byte, 16)}); !errors.Is(err, model.ErrConflict) {
		t.Fatalf("duplicate login: %v", err)
	}
	if user, err := store.FindUser(ctx, "test_"+owner); err != nil || user.ID != owner {
		t.Fatalf("find user: %+v %v", user, err)
	}
	hash := sha256.Sum256([]byte(id()))
	now := time.Now().UTC()
	if err := store.CreateSession(ctx, hash[:], owner, now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if found, err := store.SessionUser(ctx, hash[:], now); err != nil || found != owner {
		t.Fatalf("session: %s %v", found, err)
	}
	if _, err := store.SessionUser(ctx, hash[:], now.Add(time.Hour)); !errors.Is(err, model.ErrNotFound) {
		t.Fatalf("expired session: %v", err)
	}
	if err := store.DeleteSession(ctx, hash[:]); err != nil {
		t.Fatal(err)
	}
	if _, err := store.SessionUser(ctx, hash[:], now); !errors.Is(err, model.ErrNotFound) {
		t.Fatalf("revoked session: %v", err)
	}
	ciphertext := bytes.Repeat([]byte{42}, 32)
	for _, userID := range []string{owner, other} {
		if record, err := store.PutRecord(ctx, userID, entry, 0, ciphertext); err != nil || record.Revision != 1 {
			t.Fatalf("create: %+v %v", record, err)
		}
	}
	if entries, err := store.ListRecords(ctx, owner); err != nil || len(entries) != 1 || entries[0].ID != entry {
		t.Fatalf("owner snapshot: %+v %v", entries, err)
	}
	if _, err := store.GetRecord(ctx, id(), entry); !errors.Is(err, model.ErrNotFound) {
		t.Fatalf("cross-owner read: %v", err)
	}
	results := make(chan error, 2)
	for range 2 {
		go func() {
			_, err := store.PutRecord(ctx, owner, entry, 1, ciphertext)
			results <- err
		}()
	}
	var successes, conflicts int
	for range 2 {
		err := <-results
		switch {
		case err == nil:
			successes++
		case errors.Is(err, model.ErrConflict):
			conflicts++
		default:
			t.Fatal(err)
		}
	}
	if successes != 1 || conflicts != 1 {
		t.Fatalf("concurrent revision update: successes=%d conflicts=%d", successes, conflicts)
	}
	if record, err := store.GetRecord(ctx, other, entry); err != nil || record.Revision != 1 {
		t.Fatalf("other owner was modified: %+v %v", record, err)
	}
	if err := store.DeleteRecord(ctx, owner, entry, 1); !errors.Is(err, model.ErrConflict) {
		t.Fatalf("stale deletion: %v", err)
	}
	if err := store.DeleteRecord(ctx, owner, entry, 2); err != nil {
		t.Fatal(err)
	}
	if _, err := store.GetRecord(ctx, owner, entry); !errors.Is(err, model.ErrNotFound) {
		t.Fatalf("deleted record remains: %v", err)
	}
	for _, size := range []int{model.MaxCiphertextSize, model.MaxCiphertextSize, model.MaxCiphertextSize,
		model.MaxCiphertextSize, model.MaxCiphertextSize, model.MaxVaultCiphertextSize - 5*model.MaxCiphertextSize - 32} {
		if _, err := store.db.ExecContext(ctx,
			`INSERT INTO records (user_id, id, revision, ciphertext) VALUES ($1, $2, 1, repeat('a', $3)::bytea)`,
			owner, id(), size); err != nil {
			t.Fatal(err)
		}
	}
	for range 2 {
		newID := id()
		go func() {
			_, err := store.PutRecord(ctx, owner, newID, 0, make([]byte, 32))
			results <- err
		}()
	}
	successes, rejected := 0, 0
	for range 2 {
		err := <-results
		switch {
		case err == nil:
			successes++
		case errors.Is(err, model.ErrCapacity):
			rejected++
		default:
			t.Fatal(err)
		}
	}
	if successes != 1 || rejected != 1 {
		t.Fatalf("concurrent capacity enforcement: successes=%d rejected=%d", successes, rejected)
	}
}
