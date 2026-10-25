package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ndreuu/go-gophkeeper/internal/client"
	"github.com/ndreuu/go-gophkeeper/internal/cryptoutil"
	"github.com/ndreuu/go-gophkeeper/internal/model"
	"github.com/ndreuu/go-gophkeeper/internal/service"
	"go.uber.org/zap"
)

type memoryStore struct {
	mu       sync.Mutex
	users    map[string]model.User
	sessions map[string]session
	entries  map[string]map[string]model.Record
}
type session struct {
	user   string
	expiry time.Time
}

func newMemoryStore() *memoryStore {
	return &memoryStore{users: map[string]model.User{}, sessions: map[string]session{}, entries: map[string]map[string]model.Record{}}
}
func (m *memoryStore) CreateUser(_ context.Context, u model.User) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.users[u.Login]; ok {
		return model.ErrConflict
	}
	m.users[u.Login] = u
	m.entries[u.ID] = map[string]model.Record{}
	return nil
}
func (m *memoryStore) FindUser(_ context.Context, name string) (model.User, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	u, ok := m.users[name]
	if !ok {
		return u, model.ErrNotFound
	}
	return u, nil
}
func (m *memoryStore) CreateSession(_ context.Context, hash []byte, user string, expiry time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sessions[string(hash)] = session{user, expiry}
	return nil
}
func (m *memoryStore) SessionUser(_ context.Context, hash []byte, now time.Time) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.sessions[string(hash)]
	if !ok || !s.expiry.After(now) {
		return "", model.ErrNotFound
	}
	return s.user, nil
}
func (m *memoryStore) DeleteSession(_ context.Context, hash []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.sessions, string(hash))
	return nil
}
func (m *memoryStore) ListRecords(_ context.Context, user string) ([]model.Record, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	result := []model.Record{}
	for _, r := range m.entries[user] {
		result = append(result, r)
	}
	return result, nil
}
func (m *memoryStore) GetRecord(_ context.Context, user, id string) (model.Record, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	r, ok := m.entries[user][id]
	if !ok {
		return r, model.ErrNotFound
	}
	return r, nil
}
func (m *memoryStore) PutRecord(_ context.Context, user, id string, revision int64, cipher []byte) (model.Record, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	r, exists := m.entries[user][id]
	if !exists && revision != 0 {
		return r, model.ErrNotFound
	}
	if exists && r.Revision != revision {
		return r, model.ErrConflict
	}
	r = model.Record{ID: id, Revision: revision + 1, Ciphertext: cipher, UpdatedAt: time.Now().UTC()}
	m.entries[user][id] = r
	return r, nil
}
func (m *memoryStore) DeleteRecord(_ context.Context, user, id string, revision int64) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	r, ok := m.entries[user][id]
	if !ok {
		return model.ErrNotFound
	}
	if r.Revision != revision {
		return model.ErrConflict
	}
	delete(m.entries[user], id)
	return nil
}
func (m *memoryStore) Ping(context.Context) error { return nil }

func TestTwoClientsEncryptedVaultLifecycle(t *testing.T) {
	store := newMemoryStore()
	svc := service.New(store, time.Hour)
	server := httptest.NewTLSServer(New(svc, store.Ping, zap.NewNop()))
	defer server.Close()
	caFile := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	newClient := func() *client.Client {
		c, err := client.New(server.URL, caFile)
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	ctx := context.Background()
	first, second, other := newClient(), newClient(), newClient()
	creds := model.Credentials{Login: "alice", Password: "account-password"}
	auth, err := first.Register(ctx, creds)
	if err != nil {
		t.Fatal(err)
	}
	first.SetToken(auth.Token)
	secondAuth, err := second.Login(ctx, creds)
	if err != nil {
		t.Fatal(err)
	}
	second.SetToken(secondAuth.Token)
	if !bytes.Equal(auth.VaultSalt, secondAuth.VaultSalt) {
		t.Fatal("vault salt changed on another device")
	}
	if _, err = first.Register(ctx, creds); !errors.Is(err, model.ErrConflict) {
		t.Fatalf("duplicate account: %v", err)
	}
	if _, err = first.Login(ctx, model.Credentials{Login: "alice", Password: "wrong-password"}); !errors.Is(err, model.ErrUnauthorized) {
		t.Fatalf("wrong password: %v", err)
	}
	otherAuth, err := other.Register(ctx, model.Credentials{Login: "bob", Password: "other-password"})
	if err != nil {
		t.Fatal(err)
	}
	other.SetToken(otherAuth.Token)
	id, err := cryptoutil.NewID()
	if err != nil {
		t.Fatal(err)
	}
	key, err := cryptoutil.DeriveKey("vault-master-password", auth.VaultSalt)
	if err != nil {
		t.Fatal(err)
	}
	text := "private note"
	secret := model.Secret{Kind: model.KindText, Title: "Private title", Text: &text, Metadata: map[string]string{"site": "private.example"}}
	cipher, err := cryptoutil.Encrypt(key, id, secret)
	if err != nil {
		t.Fatal(err)
	}
	created, err := first.Put(ctx, id, model.PutRequest{Ciphertext: cipher})
	if err != nil || created.Revision != 1 {
		t.Fatalf("create: %+v %v", created, err)
	}
	entries, err := second.List(ctx)
	if err != nil || len(entries) != 1 {
		t.Fatalf("sync: %+v %v", entries, err)
	}
	decrypted, err := cryptoutil.Decrypt(key, id, entries[0].Ciphertext)
	if err != nil || decrypted.Title != secret.Title || *decrypted.Text != text {
		t.Fatalf("decrypt: %+v %v", decrypted, err)
	}
	for _, plain := range []string{secret.Title, text, "private.example"} {
		if bytes.Contains(created.Ciphertext, []byte(plain)) {
			t.Fatalf("stored plaintext %q", plain)
		}
	}
	if _, err = other.Get(ctx, id); !errors.Is(err, model.ErrNotFound) {
		t.Fatalf("owner isolation get: %v", err)
	}
	if err = other.Delete(ctx, id, 1); !errors.Is(err, model.ErrNotFound) {
		t.Fatalf("owner isolation delete: %v", err)
	}
	if _, err = other.Put(ctx, id, model.PutRequest{ExpectedRevision: 1, Ciphertext: cipher}); !errors.Is(err, model.ErrNotFound) {
		t.Fatalf("owner isolation update: %v", err)
	}
	updated, err := second.Put(ctx, id, model.PutRequest{ExpectedRevision: 1, Ciphertext: cipher})
	if err != nil || updated.Revision != 2 {
		t.Fatalf("update: %+v %v", updated, err)
	}
	if _, err = first.Put(ctx, id, model.PutRequest{ExpectedRevision: 1, Ciphertext: cipher}); !errors.Is(err, model.ErrConflict) {
		t.Fatalf("stale write: %v", err)
	}
	if err = first.Delete(ctx, id, 1); !errors.Is(err, model.ErrConflict) {
		t.Fatalf("stale delete: %v", err)
	}
	if err = second.Delete(ctx, id, 2); err != nil {
		t.Fatal(err)
	}
	entries, err = first.List(ctx)
	if err != nil || len(entries) != 0 {
		t.Fatalf("sync deletion: %+v %v", entries, err)
	}
	if err = first.Logout(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err = first.List(ctx); !errors.Is(err, model.ErrUnauthorized) {
		t.Fatalf("revoked session: %v", err)
	}
	if _, err = second.List(ctx); err != nil {
		t.Fatalf("independent session revoked: %v", err)
	}
}

type failingService struct {
	err       error
	panicAuth bool
}

func (f failingService) Register(context.Context, model.Credentials) (model.AuthResult, error) {
	return model.AuthResult{}, f.err
}
func (f failingService) Login(context.Context, model.Credentials) (model.AuthResult, error) {
	return model.AuthResult{}, f.err
}
func (f failingService) Authenticate(context.Context, string) (string, error) {
	if f.panicAuth {
		panic("secret panic")
	}
	return "owner", nil
}
func (f failingService) Logout(context.Context, string) error                 { return f.err }
func (f failingService) List(context.Context, string) ([]model.Record, error) { return nil, f.err }
func (f failingService) Get(context.Context, string, string) (model.Record, error) {
	return model.Record{}, f.err
}
func (f failingService) Put(context.Context, string, string, model.PutRequest) (model.Record, error) {
	return model.Record{}, f.err
}
func (f failingService) Delete(context.Context, string, string, int64) error { return f.err }

func request(router http.Handler, method, path, body, token string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	if token != "" {
		r.Header.Set("Authorization", token)
	}
	w := httptest.NewRecorder()
	router.ServeHTTP(w, r)
	return w
}

func TestErrorMappingAndParsing(t *testing.T) {
	for _, tc := range []struct {
		err    error
		status int
	}{{model.ErrInvalid, 400}, {model.ErrUnauthorized, 401}, {model.ErrNotFound, 404}, {model.ErrConflict, 409}, {model.ErrCapacity, 413}, {errors.New("database password secret"), 500}} {
		r := New(failingService{err: fmt.Errorf("wrapped: %w", tc.err)}, func(context.Context) error { return nil }, zap.NewNop())
		for _, route := range []struct{ method, path, body string }{{"POST", "/api/v1/register", `{"login":"a","password":"b"}`}, {"POST", "/api/v1/login", `{}`}, {"POST", "/api/v1/logout", ``}, {"GET", "/api/v1/entries", ``}, {"GET", "/api/v1/entries/id", ``}, {"PUT", "/api/v1/entries/id", `{}`}, {"DELETE", "/api/v1/entries/id?revision=1", ``}} {
			w := request(r, route.method, route.path, route.body, "Bearer token")
			if w.Code != tc.status || strings.Contains(w.Body.String(), "database password") {
				t.Fatalf("%s: %d %s", route.path, w.Code, w.Body.String())
			}
		}
	}
	r := New(failingService{}, func(context.Context) error { return nil }, zap.NewNop())
	for _, token := range []string{"", "Basic x", "Bearer ", "Bearer x y"} {
		if w := request(r, "GET", "/api/v1/entries", "", token); w.Code != 401 {
			t.Fatalf("auth %q: %d", token, w.Code)
		}
	}
	for _, body := range []string{"{", `{"unknown":1}`, "{} {}"} {
		if w := request(r, "POST", "/api/v1/login", body, ""); w.Code != 400 {
			t.Fatalf("body %q: %d", body, w.Code)
		}
	}
	for _, revision := range []string{"", "no", "0", "-1"} {
		if w := request(r, "DELETE", "/api/v1/entries/id?revision="+revision, "", "Bearer token"); w.Code != 400 {
			t.Fatalf("revision %q: %d", revision, w.Code)
		}
	}
	if w := request(r, "POST", "/api/v1/login", `{"password":"`+strings.Repeat("x", 9000)+`"}`, ""); w.Code != 413 {
		t.Fatalf("oversized auth %d", w.Code)
	}
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/api/v1/login", strings.NewReader("{}")))
	if w.Code != 415 {
		t.Fatalf("content-type %d", w.Code)
	}
	if w := request(r, "GET", "/api/v1/entries", "", "Bearer token"); w.Code != 200 || !strings.Contains(w.Body.String(), `"entries":[]`) {
		t.Fatalf("empty snapshot: %s", w.Body.String())
	}
	if w := request(r, "GET", "/healthz", "", ""); w.Code != 200 || w.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("health: %d", w.Code)
	}
	r = New(failingService{}, func(context.Context) error { return errors.New("offline") }, zap.NewNop())
	if w := request(r, "GET", "/healthz", "", ""); w.Code != 503 {
		t.Fatalf("health unavailable %d", w.Code)
	}
	r = New(failingService{panicAuth: true}, func(context.Context) error { return nil }, zap.NewNop())
	if w := request(r, "GET", "/api/v1/entries", "", "Bearer token"); w.Code != 500 || strings.Contains(w.Body.String(), "secret") {
		t.Fatalf("recovery %d %s", w.Code, w.Body.String())
	}
}

func TestMaximumCiphertextFitsJSONEnvelope(t *testing.T) {
	body, err := json.Marshal(model.PutRequest{Ciphertext: make([]byte, model.MaxCiphertextSize)})
	if err != nil {
		t.Fatal(err)
	}
	r := New(failingService{}, func(context.Context) error { return nil }, zap.NewNop())
	if w := request(r, "PUT", "/api/v1/entries/id", string(body), "Bearer token"); w.Code != 200 {
		t.Fatalf("maximum valid ciphertext rejected: %d", w.Code)
	}
}
