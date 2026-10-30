package service

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"io"
	"math"
	"strings"
	"testing"
	"time"

	"github.com/ndreuu/go-gophkeeper/internal/model"
)

const (
	testOwner = "0123456789abcdef0123456789abcdef"
	testID    = "abcdef0123456789abcdef0123456789"
)

type fakeSession struct {
	owner   string
	expires time.Time
}

type cancelOnWaitContext struct {
	context.Context
	cancel context.CancelFunc
}

func (c cancelOnWaitContext) Done() <-chan struct{} {
	c.cancel()
	return c.Context.Done()
}

type fakeStore struct {
	users    map[string]model.User
	sessions map[string]fakeSession
	records  map[string]model.Record
	failure  error
}

func newFakeStore() *fakeStore {
	return &fakeStore{users: map[string]model.User{}, sessions: map[string]fakeSession{}, records: map[string]model.Record{}}
}

func (f *fakeStore) CreateUser(_ context.Context, user model.User) error {
	if f.failure != nil {
		return f.failure
	}
	if _, exists := f.users[user.Login]; exists {
		return model.ErrConflict
	}
	f.users[user.Login] = user
	return nil
}

func (f *fakeStore) FindUser(_ context.Context, login string) (model.User, error) {
	if f.failure != nil {
		return model.User{}, f.failure
	}
	user, exists := f.users[login]
	if !exists {
		return model.User{}, model.ErrNotFound
	}
	return user, nil
}

func (f *fakeStore) CreateSession(_ context.Context, hash []byte, owner string, expires time.Time) error {
	if f.failure != nil {
		return f.failure
	}
	f.sessions[string(hash)] = fakeSession{owner, expires}
	return nil
}

func (f *fakeStore) SessionUser(_ context.Context, hash []byte, now time.Time) (string, error) {
	if f.failure != nil {
		return "", f.failure
	}
	session, ok := f.sessions[string(hash)]
	if !ok || !now.Before(session.expires) {
		return "", model.ErrNotFound
	}
	return session.owner, nil
}

func (f *fakeStore) DeleteSession(_ context.Context, hash []byte) error {
	delete(f.sessions, string(hash))
	return f.failure
}

func (f *fakeStore) ListRecords(_ context.Context, owner string) ([]model.Record, error) {
	if f.failure != nil {
		return nil, f.failure
	}
	var result []model.Record
	for key, record := range f.records {
		if strings.HasPrefix(key, owner+"/") {
			result = append(result, record)
		}
	}
	return result, nil
}

func (f *fakeStore) GetRecord(_ context.Context, owner, id string) (model.Record, error) {
	if f.failure != nil {
		return model.Record{}, f.failure
	}
	record, ok := f.records[owner+"/"+id]
	if !ok {
		return model.Record{}, model.ErrNotFound
	}
	return record, nil
}

func (f *fakeStore) PutRecord(ctx context.Context, owner, id string, expected int64, ciphertext []byte) (model.Record, error) {
	if f.failure != nil {
		return model.Record{}, f.failure
	}
	previous, err := f.GetRecord(ctx, owner, id)
	if expected != 0 && err != nil {
		return model.Record{}, err
	}
	if expected != previous.Revision {
		return model.Record{}, model.ErrConflict
	}
	record := model.Record{ID: id, Revision: expected + 1, Ciphertext: ciphertext, UpdatedAt: time.Now().UTC()}
	f.records[owner+"/"+id] = record
	return record, nil
}

func (f *fakeStore) DeleteRecord(ctx context.Context, owner, id string, expected int64) error {
	record, err := f.GetRecord(ctx, owner, id)
	if err != nil {
		return err
	}
	if expected != record.Revision {
		return model.ErrConflict
	}
	delete(f.records, owner+"/"+id)
	return nil
}

func TestRegistrationLoginAndSessionLifecycle(t *testing.T) {
	ctx := context.Background()
	store := newFakeStore()
	service := New(store, time.Hour)
	now := time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC)
	service.now = func() time.Time { return now }
	credentials := model.Credentials{Login: "alice", Password: "password-with-spaces 123"}
	registered, err := service.Register(ctx, credentials)
	if err != nil {
		t.Fatal(err)
	}
	user := store.users[credentials.Login]
	if !model.ValidID(user.ID) || len(user.VaultSalt) != 16 || !registered.ExpiresAt.Equal(now.Add(time.Hour)) {
		t.Fatalf("invalid account/session: user=%+v expiry=%v", user, registered.ExpiresAt)
	}
	if strings.Contains(user.PasswordHash, credentials.Password) || !verifyPassword(credentials.Password, user.PasswordHash) {
		t.Fatal("password was not stored as a verifiable Argon2id hash")
	}
	digest := sha256.Sum256([]byte(registered.Token))
	if _, ok := store.sessions[string(digest[:])]; !ok || len(store.sessions) != 1 {
		t.Fatal("session must contain SHA-256 token digest")
	}
	if _, ok := store.sessions[registered.Token]; ok {
		t.Fatal("raw bearer token persisted")
	}
	if id, err := service.Authenticate(ctx, registered.Token); err != nil || id != user.ID {
		t.Fatalf("authenticate: id=%q err=%v", id, err)
	}
	loggedIn, err := service.Login(ctx, credentials)
	if err != nil || loggedIn.Token == registered.Token || !bytes.Equal(loggedIn.VaultSalt, registered.VaultSalt) {
		t.Fatalf("login must rotate token and preserve vault salt: err=%v", err)
	}
	if err := service.Logout(ctx, registered.Token); err != nil {
		t.Fatal(err)
	}
	if _, err := service.Authenticate(ctx, registered.Token); !errors.Is(err, model.ErrUnauthorized) {
		t.Fatalf("revoked token accepted: %v", err)
	}
	if err := service.Logout(ctx, registered.Token); err != nil {
		t.Fatalf("logout should be idempotent: %v", err)
	}
	now = loggedIn.ExpiresAt
	if _, err := service.Authenticate(ctx, loggedIn.Token); !errors.Is(err, model.ErrUnauthorized) {
		t.Fatalf("token accepted at expiry boundary: %v", err)
	}
	if _, err := service.Register(ctx, credentials); !errors.Is(err, model.ErrConflict) {
		t.Fatalf("duplicate account: %v", err)
	}
}

func TestCredentialsValidation(t *testing.T) {
	for _, credentials := range []model.Credentials{
		{Login: "ab", Password: "12345678"}, {Login: strings.Repeat("a", 65), Password: "12345678"},
		{Login: "alice", Password: "1234567"}, {Login: "alice", Password: strings.Repeat("x", 1025)},
		{Login: "ali ce", Password: "12345678"}, {Login: "али", Password: "12345678"},
	} {
		service := New(newFakeStore(), 0)
		if _, err := service.Register(context.Background(), credentials); !errors.Is(err, model.ErrInvalid) {
			t.Fatalf("Register(%q)=%v", credentials.Login, err)
		}
		if _, err := service.Login(context.Background(), credentials); !errors.Is(err, model.ErrInvalid) {
			t.Fatalf("Login(%q)=%v", credentials.Login, err)
		}
	}
	if err := validateCredentials(model.Credentials{Login: "A-z_9.name", Password: "12345678"}); err != nil {
		t.Fatal(err)
	}
}

func TestLoginRejectsUnknownWrongAndCorruptPasswords(t *testing.T) {
	store := newFakeStore()
	store.users["alice"] = model.User{ID: testOwner, PasswordHash: hashPassword("correct-password", bytes.Repeat([]byte{1}, 16))}
	service := New(store, time.Hour)
	for _, credentials := range []model.Credentials{
		{Login: "nobody", Password: "correct-password"}, {Login: "alice", Password: "wrong-password"},
	} {
		if _, err := service.Login(context.Background(), credentials); !errors.Is(err, model.ErrUnauthorized) {
			t.Fatalf("invalid login error: %v", err)
		}
	}
	store.users["alice"] = model.User{PasswordHash: "corrupt"}
	if _, err := service.Login(context.Background(), model.Credentials{Login: "alice", Password: "correct-password"}); !errors.Is(err, model.ErrUnauthorized) {
		t.Fatalf("corrupt hash error: %v", err)
	}
	if len(store.sessions) != 0 {
		t.Fatal("failed authentication created a session")
	}
}

func TestAuthenticationErrorsAndRandomnessFailures(t *testing.T) {
	ctx := context.Background()
	store := newFakeStore()
	service := New(store, 0)
	if service.sessionTTL != 24*time.Hour {
		t.Fatal("default session lifetime")
	}
	credentials := model.Credentials{Login: "alice", Password: "password123"}
	for _, randomSize := range []int{0, 16, 32, 48} {
		candidate := New(newFakeStore(), time.Hour)
		candidate.random = bytes.NewReader(make([]byte, randomSize))
		if _, err := candidate.Register(ctx, credentials); !errors.Is(err, io.EOF) {
			t.Fatalf("random source length %d: %v", randomSize, err)
		}
	}
	problem := errors.New("database unavailable")
	store.failure = problem
	if _, err := service.Register(ctx, credentials); !errors.Is(err, problem) {
		t.Fatalf("registration storage failure: %v", err)
	}
	if _, err := service.Login(ctx, credentials); !errors.Is(err, problem) {
		t.Fatalf("login storage failure: %v", err)
	}
	if _, err := service.startSession(ctx, model.User{ID: testOwner}); !errors.Is(err, problem) {
		t.Fatalf("session storage failure: %v", err)
	}
	validToken := strings.Repeat("A", 43)
	if _, err := service.Authenticate(ctx, validToken); !errors.Is(err, problem) {
		t.Fatalf("session lookup failure: %v", err)
	}
	if err := service.Logout(ctx, validToken); !errors.Is(err, problem) {
		t.Fatalf("revocation failure: %v", err)
	}
	for _, token := range []string{"", "short", strings.Repeat("A", 42), strings.Repeat("A", 42) + "B", strings.Repeat("!", 43)} {
		if _, err := service.Authenticate(ctx, token); !errors.Is(err, model.ErrUnauthorized) {
			t.Fatalf("malformed token accepted: %v", err)
		}
		if err := service.Logout(ctx, token); !errors.Is(err, model.ErrUnauthorized) {
			t.Fatalf("malformed logout token accepted: %v", err)
		}
	}
}

func TestOwnerScopeAndOptimisticRevisions(t *testing.T) {
	ctx := context.Background()
	service := New(newFakeStore(), time.Hour)
	if records, err := service.List(ctx, testOwner); err != nil || records == nil || len(records) != 0 {
		t.Fatalf("empty snapshot: %v %v", records, err)
	}
	request := model.PutRequest{Ciphertext: bytes.Repeat([]byte{1}, 28)}
	created, err := service.Put(ctx, testOwner, testID, request)
	if err != nil || created.Revision != 1 || !bytes.Equal(created.Ciphertext, request.Ciphertext) {
		t.Fatalf("create: %+v %v", created, err)
	}
	if _, err := service.Put(ctx, testOwner, testID, request); !errors.Is(err, model.ErrConflict) {
		t.Fatalf("duplicate create: %v", err)
	}
	otherOwner := strings.Repeat("1", 32)
	if _, err := service.Get(ctx, otherOwner, testID); !errors.Is(err, model.ErrNotFound) {
		t.Fatalf("other owner can read record: %v", err)
	}
	if records, err := service.List(ctx, otherOwner); err != nil || len(records) != 0 {
		t.Fatalf("other owner can list record: %v %v", records, err)
	}
	if err := service.Delete(ctx, otherOwner, testID, 1); !errors.Is(err, model.ErrNotFound) {
		t.Fatalf("other owner can delete record: %v", err)
	}
	request.ExpectedRevision = 1
	request.Ciphertext[0] = 2
	updated, err := service.Put(ctx, testOwner, testID, request)
	if err != nil || updated.Revision != 2 {
		t.Fatalf("update: %+v %v", updated, err)
	}
	if _, err := service.Put(ctx, testOwner, testID, request); !errors.Is(err, model.ErrConflict) {
		t.Fatalf("stale update: %v", err)
	}
	if err := service.Delete(ctx, testOwner, testID, 1); !errors.Is(err, model.ErrConflict) {
		t.Fatalf("stale delete: %v", err)
	}
	if records, err := service.List(ctx, testOwner); err != nil || len(records) != 1 || records[0].Revision != 2 {
		t.Fatalf("snapshot: %v %v", records, err)
	}
	if record, err := service.Get(ctx, testOwner, testID); err != nil || record.Revision != 2 {
		t.Fatalf("get latest: %+v %v", record, err)
	}
	if err := service.Delete(ctx, testOwner, testID, 2); err != nil {
		t.Fatal(err)
	}
	if _, err := service.Get(ctx, testOwner, testID); !errors.Is(err, model.ErrNotFound) {
		t.Fatalf("deleted entry remains: %v", err)
	}
}

func TestRecordValidationAndStorageFailures(t *testing.T) {
	ctx := context.Background()
	store := newFakeStore()
	service := New(store, time.Hour)
	valid := model.PutRequest{Ciphertext: make([]byte, 28)}
	for _, owner := range []string{"", "bad", strings.Repeat("A", 32)} {
		if _, err := service.List(ctx, owner); !errors.Is(err, model.ErrUnauthorized) {
			t.Fatalf("invalid list owner: %v", err)
		}
		if _, err := service.Get(ctx, owner, testID); !errors.Is(err, model.ErrUnauthorized) {
			t.Fatalf("invalid get owner: %v", err)
		}
		if _, err := service.Put(ctx, owner, testID, valid); !errors.Is(err, model.ErrUnauthorized) {
			t.Fatalf("invalid put owner: %v", err)
		}
		if err := service.Delete(ctx, owner, testID, 1); !errors.Is(err, model.ErrUnauthorized) {
			t.Fatalf("invalid delete owner: %v", err)
		}
	}
	for _, id := range []string{"bad", strings.Repeat("A", 32)} {
		if _, err := service.Get(ctx, testOwner, id); !errors.Is(err, model.ErrInvalid) {
			t.Fatalf("invalid id: %v", err)
		}
	}
	for _, request := range []model.PutRequest{
		{ExpectedRevision: -1, Ciphertext: make([]byte, 28)},
		{ExpectedRevision: math.MaxInt64, Ciphertext: make([]byte, 28)},
		{Ciphertext: make([]byte, 27)}, {Ciphertext: make([]byte, model.MaxCiphertextSize+1)},
	} {
		if _, err := service.Put(ctx, testOwner, testID, request); !errors.Is(err, model.ErrInvalid) {
			t.Fatalf("invalid request accepted: %v", err)
		}
	}
	for _, revision := range []int64{-1, 0} {
		if err := service.Delete(ctx, testOwner, testID, revision); !errors.Is(err, model.ErrInvalid) {
			t.Fatalf("invalid delete revision: %v", err)
		}
	}
	problem := errors.New("storage failure")
	store.failure = problem
	if _, err := service.List(ctx, testOwner); !errors.Is(err, problem) {
		t.Fatalf("list storage error: %v", err)
	}
	if _, err := service.Get(ctx, testOwner, testID); !errors.Is(err, problem) {
		t.Fatalf("get storage error: %v", err)
	}
	if _, err := service.Put(ctx, testOwner, testID, valid); !errors.Is(err, problem) {
		t.Fatalf("put storage error: %v", err)
	}
	if err := service.Delete(ctx, testOwner, testID, 1); !errors.Is(err, problem) {
		t.Fatalf("delete storage error: %v", err)
	}
}

func TestPasswordEncodingRejectsMalformedParameters(t *testing.T) {
	encoded := hashPassword("password123", make([]byte, 16))
	for _, corrupt := range []string{
		"", "argon2id", strings.Replace(encoded, "v=19", "v=20", 1),
		strings.Replace(encoded, "m=65536", "m=4294967295", 1),
		"$argon2id$v=19$m=65536,t=3,p=2$!$AAAA",
		"$argon2id$v=19$m=65536,t=3,p=2$AAAA$AAAA",
		strings.Join(strings.Split(encoded, "$")[:5], "$") + "$!",
		strings.Join(strings.Split(encoded, "$")[:5], "$") + "$AAAA",
	} {
		if verifyPassword("password123", corrupt) {
			t.Fatal("malformed password encoding accepted")
		}
	}
}

func TestPasswordWorkIsBoundedAndWaitingRequestsCanCancel(t *testing.T) {
	store := newFakeStore()
	store.users["alice"] = model.User{ID: testOwner, PasswordHash: "unused"}
	service := New(store, time.Hour)
	if cap(service.passwordSlots) != 4 {
		t.Fatal("expected at most four simultaneous 64 MiB password derivations")
	}
	for range cap(service.passwordSlots) {
		service.passwordSlots <- struct{}{}
	}
	for _, operation := range []string{"register", "existing login", "missing login"} {
		t.Run(operation, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			result := make(chan error, 1)
			go func() {
				credentials := model.Credentials{Login: "alice", Password: "password123"}
				var err error
				if operation == "register" {
					_, err = service.Register(ctx, credentials)
				} else {
					if operation == "missing login" {
						credentials.Login = "nobody"
					}
					_, err = service.Login(ctx, credentials)
				}
				result <- err
			}()
			select {
			case err := <-result:
				t.Fatalf("saturated password worker did not wait: %v", err)
			case <-time.After(10 * time.Millisecond):
			}
			cancel()
			select {
			case err := <-result:
				if !errors.Is(err, context.Canceled) {
					t.Fatalf("queued cancellation: %v", err)
				}
			case <-time.After(time.Second):
				t.Fatal("cancelled password request stayed queued")
			}
		})
	}
	for range cap(service.passwordSlots) {
		<-service.passwordSlots
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := service.acquirePasswordSlot(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("already cancelled password work accepted: %v", err)
	}
	if len(service.passwordSlots) != 0 || len(store.sessions) != 0 {
		t.Fatal("cancelled password work leaked a slot or issued a session")
	}
}

func TestMasterVerifierCanOnlyBeCreatedOnce(t *testing.T) {
	ctx := context.Background()
	service := New(newFakeStore(), time.Hour)
	request := model.PutRequest{Ciphertext: make([]byte, 28)}
	if _, err := service.Put(ctx, testOwner, model.MasterVerifierID, request); err != nil {
		t.Fatal(err)
	}
	if _, err := service.Put(ctx, testOwner, model.MasterVerifierID, request); !errors.Is(err, model.ErrConflict) {
		t.Fatalf("second verifier creation accepted: %v", err)
	}
	request.ExpectedRevision = 1
	if _, err := service.Put(ctx, testOwner, model.MasterVerifierID, request); !errors.Is(err, model.ErrInvalid) {
		t.Fatalf("verifier replacement accepted: %v", err)
	}
	if err := service.Delete(ctx, testOwner, model.MasterVerifierID, 1); !errors.Is(err, model.ErrInvalid) {
		t.Fatalf("verifier deletion accepted: %v", err)
	}
	if record, err := service.Get(ctx, testOwner, model.MasterVerifierID); err != nil || record.Revision != 1 {
		t.Fatalf("verifier was changed: %+v %v", record, err)
	}
}

func TestCancelledWaiterDoesNotKeepAnAvailablePasswordSlot(t *testing.T) {
	service := New(newFakeStore(), time.Hour)
	for range 100 {
		ctx, cancel := context.WithCancel(context.Background())
		err := service.acquirePasswordSlot(cancelOnWaitContext{Context: ctx, cancel: cancel})
		if !errors.Is(err, context.Canceled) || len(service.passwordSlots) != 0 {
			t.Fatalf("cancelled acquire kept a slot: err=%v used=%d", err, len(service.passwordSlots))
		}
	}
}
