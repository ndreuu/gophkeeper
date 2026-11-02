package cli

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ndreuu/go-gophkeeper/internal/cryptoutil"
	"github.com/ndreuu/go-gophkeeper/internal/model"
)

type fakeVault struct {
	mu                 sync.Mutex
	records            map[string]model.Record
	failList           bool
	failAuth           bool
	failLogout         bool
	unauthorizedLogout bool
	puts               int
	password           string
	beforeMarkerPut    func()
}

func (v *fakeVault) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPut && r.URL.Path == "/api/v1/entries/"+model.MasterVerifierID && v.beforeMarkerPut != nil {
		v.beforeMarkerPut()
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	if r.URL.Path == "/api/v1/login" || r.URL.Path == "/api/v1/register" {
		var credentials model.Credentials
		if err := json.NewDecoder(r.Body).Decode(&credentials); err != nil {
			w.WriteHeader(400)
			return
		}
		v.password = credentials.Password
		if v.failAuth {
			w.WriteHeader(401)
			fmt.Fprint(w, `{"error":"invalid credentials"}`)
			return
		}
		if strings.HasSuffix(r.URL.Path, "register") {
			w.WriteHeader(201)
		}
		json.NewEncoder(w).Encode(model.AuthResult{Token: "token-secret", VaultSalt: []byte("1234567890abcdef"), ExpiresAt: time.Now().Add(time.Hour)})
		return
	}
	if r.Header.Get("Authorization") != "Bearer token-secret" {
		w.WriteHeader(401)
		fmt.Fprint(w, `{"error":"unauthorized"}`)
		return
	}
	if r.URL.Path == "/api/v1/logout" {
		if v.failLogout {
			w.WriteHeader(500)
			fmt.Fprint(w, `{"error":"failed"}`)
			return
		}
		if v.unauthorizedLogout {
			w.WriteHeader(401)
			fmt.Fprint(w, `{"error":"expired"}`)
			return
		}
		w.WriteHeader(204)
		return
	}
	if r.URL.Path == "/api/v1/entries" {
		if v.failList {
			w.WriteHeader(500)
			fmt.Fprint(w, `{"error":"failed"}`)
			return
		}
		records := make([]model.Record, 0, len(v.records))
		for _, record := range v.records {
			records = append(records, record)
		}
		json.NewEncoder(w).Encode(map[string]any{"entries": records})
		return
	}
	id := strings.TrimPrefix(r.URL.Path, "/api/v1/entries/")
	switch r.Method {
	case http.MethodGet:
		record, exists := v.records[id]
		if !exists {
			w.WriteHeader(404)
			fmt.Fprint(w, `{"error":"missing"}`)
			return
		}
		json.NewEncoder(w).Encode(record)
	case http.MethodPut:
		var req model.PutRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			w.WriteHeader(400)
			return
		}
		record, exists := v.records[id]
		if (!exists && req.ExpectedRevision != 0) || (exists && record.Revision != req.ExpectedRevision) {
			w.WriteHeader(409)
			fmt.Fprint(w, `{"error":"revision conflict"}`)
			return
		}
		v.puts++
		record = model.Record{ID: id, Revision: req.ExpectedRevision + 1, Ciphertext: req.Ciphertext, UpdatedAt: time.Now()}
		v.records[id] = record
		json.NewEncoder(w).Encode(record)
	case http.MethodDelete:
		record, exists := v.records[id]
		if !exists {
			w.WriteHeader(404)
			fmt.Fprint(w, `{"error":"missing"}`)
			return
		}
		if r.URL.Query().Get("revision") != fmt.Sprint(record.Revision) {
			w.WriteHeader(409)
			fmt.Fprint(w, `{"error":"revision conflict"}`)
			return
		}
		delete(v.records, id)
		w.WriteHeader(204)
	default:
		w.WriteHeader(404)
	}
}

type cliFixture struct {
	vault     *fakeVault
	args      []string
	statePath string
	dir       string
}

func newFixture(t *testing.T) *cliFixture {
	t.Helper()
	vault := &fakeVault{records: make(map[string]model.Record)}
	server := httptest.NewTLSServer(vault)
	t.Cleanup(server.Close)
	return fixtureForServer(t, vault, server)
}

func fixtureForServer(t *testing.T, vault *fakeVault, server *httptest.Server) *cliFixture {
	t.Helper()
	dir := t.TempDir()
	ca := filepath.Join(dir, "ca.pem")
	if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	statePath := filepath.Join(dir, "private", "state.json")
	return &cliFixture{vault: vault, args: []string{"-server-url", server.URL, "-ca-file", ca, "-state-file", statePath}, statePath: statePath, dir: dir}
}

func TestMultipleClientsSynchronizeAndReplaceAccountCache(t *testing.T) {
	var mu sync.Mutex
	owners := make(map[string]*fakeVault)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/login" || r.URL.Path == "/api/v1/register" {
			var credentials model.Credentials
			if err := json.NewDecoder(r.Body).Decode(&credentials); err != nil {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			salt := sha256.Sum256([]byte(credentials.Login))
			json.NewEncoder(w).Encode(model.AuthResult{Token: "token-" + credentials.Login, VaultSalt: salt[:16], ExpiresAt: time.Now().Add(time.Hour)})
			return
		}
		owner := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer token-")
		mu.Lock()
		vault := owners[owner]
		if vault == nil {
			vault = &fakeVault{records: make(map[string]model.Record)}
			owners[owner] = vault
		}
		mu.Unlock()
		r.Header.Set("Authorization", "Bearer token-secret")
		vault.ServeHTTP(w, r)
	}))
	t.Cleanup(server.Close)
	a := fixtureForServer(t, nil, server)
	b := fixtureForServer(t, nil, server)
	a.login(t)
	b.login(t)
	text := "first revision"
	file := writeSecret(t, a.dir, "secret.json", model.Secret{Kind: model.KindText, Title: "Shared", Text: &text})
	out, err := a.run(t, "master-pass\nmaster-pass\n", "put", "-file", file)
	if err != nil {
		t.Fatal(err)
	}
	id := recordID(t, out)
	out, err = b.run(t, "master-pass\n", "list")
	if err != nil || !strings.Contains(out, id) || !strings.Contains(out, `"revision":1`) {
		t.Fatalf("second client did not see creation: %s: %v", out, err)
	}
	text = "second revision"
	file = writeSecret(t, a.dir, "secret.json", model.Secret{Kind: model.KindText, Title: "Shared", Text: &text})
	if _, err := a.run(t, "master-pass\n", "put", "-file", file, "-id", id, "-revision", "1"); err != nil {
		t.Fatal(err)
	}
	if _, err := b.run(t, "master-pass\n", "put", "-file", file, "-id", id, "-revision", "1"); !errors.Is(err, model.ErrConflict) {
		t.Fatalf("stale second client overwrote newer data: %v", err)
	}
	out, err = b.run(t, "master-pass\n", "get", id)
	if err != nil || !strings.Contains(out, text) {
		t.Fatalf("second client did not see update: %s: %v", out, err)
	}
	if _, err := a.run(t, "", "delete", "-revision", "2", id); err != nil {
		t.Fatal(err)
	}
	out, err = b.run(t, "", "sync")
	if err != nil || !strings.Contains(out, `"entries":0`) {
		t.Fatalf("second client retained deletion: %s: %v", out, err)
	}
	if _, err := a.run(t, "master-pass\n", "put", "-file", file); err != nil {
		t.Fatal(err)
	}
	if _, err := b.run(t, "", "sync"); err != nil {
		t.Fatal(err)
	}
	before, err := loadState(config{ServerURL: server.URL, StateFile: b.statePath})
	if err != nil || len(before.Records) != 2 {
		t.Fatalf("missing previous account cache: %+v: %v", before, err)
	}
	if _, err := b.run(t, "another-pass\n", "login", "-login", "bob"); err != nil {
		t.Fatal(err)
	}
	after, err := loadState(config{ServerURL: server.URL, StateFile: b.statePath})
	if err != nil || len(after.Records) != 0 || after.Token == before.Token || bytes.Equal(after.VaultSalt, before.VaultSalt) {
		t.Fatalf("new account retained previous session/cache: %+v: %v", after, err)
	}
}

func (f *cliFixture) run(t *testing.T, input string, args ...string) (string, error) {
	t.Helper()
	var out, errOut bytes.Buffer
	all := append(append([]string{}, f.args...), args...)
	err := Run(context.Background(), all, strings.NewReader(input), &out, &errOut)
	if strings.Contains(errOut.String(), "account-pass") || strings.Contains(errOut.String(), "master-pass") {
		t.Fatal("password leaked to diagnostic output")
	}
	return out.String(), err
}

func (f *cliFixture) login(t *testing.T) {
	t.Helper()
	if _, err := f.run(t, "account-pass\n", "login", "-login", "alice"); err != nil {
		t.Fatal(err)
	}
}

func writeSecret(t *testing.T, dir, name string, secret model.Secret) string {
	t.Helper()
	data, err := json.Marshal(secret)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func recordID(t *testing.T, out string) string {
	t.Helper()
	var result struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal([]byte(out), &result); err != nil {
		t.Fatal(err)
	}
	return result.ID
}

func TestEncryptedVaultLifecycle(t *testing.T) {
	f := newFixture(t)
	if _, err := f.run(t, "account-pass\naccount-pass\n", "register", "-login", "alice"); err != nil {
		t.Fatal(err)
	}
	text := "highly-private-text"
	file := writeSecret(t, f.dir, "secret.json", model.Secret{Kind: model.KindText, Title: "Private note", Text: &text, Metadata: map[string]string{"owner": "Alice"}})
	out, err := f.run(t, "master-pass\nmaster-pass\n", "put", "-file", file)
	if err != nil {
		t.Fatal(err)
	}
	id := recordID(t, out)
	if len(id) != 32 {
		t.Fatalf("unexpected id %q", id)
	}
	persisted, err := os.ReadFile(f.statePath)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"highly-private-text", "Private note", "Alice", "account-pass", "master-pass"} {
		if bytes.Contains(persisted, []byte(secret)) {
			t.Fatalf("plaintext %q persisted", secret)
		}
	}
	out, err = f.run(t, "master-pass\n", "list")
	if err != nil || !strings.Contains(out, "Private note") || !strings.Contains(out, "Alice") || strings.Contains(out, text) {
		t.Fatalf("list %q: %v", out, err)
	}
	out, err = f.run(t, "master-pass\n", "get", id)
	if err != nil || !strings.Contains(out, text) {
		t.Fatalf("get %q: %v", out, err)
	}
	if _, err = f.run(t, "master-pass\n", "put", "-file", file, "-id", id, "-revision", "1"); err != nil {
		t.Fatal(err)
	}
	if _, err = f.run(t, "master-pass\n", "put", "-file", file, "-id", id, "-revision", "1"); !errors.Is(err, model.ErrConflict) || !strings.Contains(err.Error(), "another client") {
		t.Fatalf("stale put: %v", err)
	}
	if _, err = f.run(t, "", "delete", "-revision", "1", id); !errors.Is(err, model.ErrConflict) {
		t.Fatalf("stale delete: %v", err)
	}
	before := f.vault.puts
	if _, err = f.run(t, "wrong-master\n", "put", "-file", file); err == nil || !strings.Contains(err.Error(), "master password") {
		t.Fatalf("wrong master: %v", err)
	}
	if f.vault.puts != before {
		t.Fatal("wrote encrypted data with incorrect master password")
	}
	if _, err = f.run(t, "", "delete", id); err != nil {
		t.Fatal(err)
	}
	out, err = f.run(t, "master-pass\n", "list")
	if err != nil || strings.TrimSpace(out) != "[]" {
		t.Fatalf("empty list %q: %v", out, err)
	}
	out, err = f.run(t, "", "sync")
	if err != nil || !strings.Contains(out, `"entries":0`) {
		t.Fatalf("sync %q: %v", out, err)
	}
	if _, err = f.run(t, "", "logout"); err != nil {
		t.Fatal(err)
	}
	if _, err = os.Stat(f.statePath); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("session cache survived logout")
	}
}

func TestBinaryStdinAndExport(t *testing.T) {
	f := newFixture(t)
	f.login(t)
	secret := model.Secret{Kind: model.KindBinary, Title: "Document", Binary: &model.BinaryData{Name: "../../unsafe.bin", Data: []byte{0, 1, 255, 3}}}
	data, _ := json.Marshal(secret)
	out, err := f.run(t, "master-pass\nmaster-pass\n"+string(data), "put")
	if err != nil {
		t.Fatal(err)
	}
	id := recordID(t, out)
	destination := filepath.Join(f.dir, "exports", "document.bin")
	if _, err = f.run(t, "master-pass\n", "get", "-out", destination, id); err != nil {
		t.Fatal(err)
	}
	exported, err := os.ReadFile(destination)
	if err != nil || !bytes.Equal(exported, secret.Binary.Data) {
		t.Fatalf("export %v: %v", exported, err)
	}
	info, _ := os.Stat(destination)
	if info.Mode().Perm() != 0600 {
		t.Fatalf("permissions %o", info.Mode().Perm())
	}
	if _, err = f.run(t, "master-pass\n", "get", "-out", destination, id); !errors.Is(err, os.ErrExist) {
		t.Fatalf("binary export silently overwrote an existing file: %v", err)
	}
	if _, err = f.run(t, "wrong-master\n", "list"); err == nil {
		t.Fatal("wrong master accepted")
	}
	if _, err = f.run(t, "wrong-master\n", "get", id); err == nil {
		t.Fatal("wrong master accepted")
	}
	if _, err = f.run(t, "", "get", "missing"); !errors.Is(err, model.ErrNotFound) {
		t.Fatalf("missing: %v", err)
	}
}

func TestMasterVerifierSurvivesDeletionAndCannotBeEdited(t *testing.T) {
	f := newFixture(t)
	f.login(t)
	text := "a private value"
	file := writeSecret(t, f.dir, "secret.json", model.Secret{Kind: model.KindText, Title: "Entry", Text: &text})
	out, err := f.run(t, "master-pass\nmaster-pass\n", "put", "-file", file)
	if err != nil {
		t.Fatal(err)
	}
	id := recordID(t, out)
	if _, err := f.run(t, "", "delete", id); err != nil {
		t.Fatal(err)
	}
	marker, exists := f.vault.records[model.MasterVerifierID]
	if !exists || len(f.vault.records) != 1 {
		t.Fatal("last-entry deletion removed the permanent master verifier")
	}
	if bytes.Contains(marker.Ciphertext, []byte(verifierText)) || bytes.Contains(marker.Ciphertext, []byte("Vault key verifier")) {
		t.Fatal("verifier payload was not encrypted")
	}
	if _, err := f.run(t, "wrong-master\n", "list"); err == nil {
		t.Fatal("empty initialized vault accepted a wrong master password")
	}
	if _, err := f.run(t, "wrong-master\n", "put", "-file", file); err == nil {
		t.Fatal("empty initialized vault accepted replacement master password")
	}
	if _, err := f.run(t, "master-pass\n", "put", "-file", file); err != nil {
		t.Fatalf("original master password failed after all entries were deleted: %v", err)
	}
	for _, command := range [][]string{{"get", model.MasterVerifierID}, {"delete", model.MasterVerifierID}, {"put", "-id", model.MasterVerifierID, "-revision", "1", "-file", file}} {
		if _, err := f.run(t, "", command...); err == nil || !strings.Contains(err.Error(), "reserved") {
			t.Fatalf("reserved verifier exposed to command %v: %v", command, err)
		}
	}
	out, err = f.run(t, "master-pass\n", "list")
	if err != nil || strings.Contains(out, model.MasterVerifierID) || strings.Contains(out, verifierText) {
		t.Fatalf("list exposed verifier: %s: %v", out, err)
	}
}

func TestConcurrentFirstWritesChooseOneMasterKey(t *testing.T) {
	for _, samePassword := range []bool{false, true} {
		t.Run(fmt.Sprintf("same_password_%t", samePassword), func(t *testing.T) {
			var waiting atomic.Int32
			ready := make(chan struct{})
			vault := &fakeVault{records: make(map[string]model.Record)}
			vault.beforeMarkerPut = func() {
				if waiting.Add(1) == 2 {
					close(ready)
				}
				select {
				case <-ready:
				case <-time.After(5 * time.Second):
					t.Error("concurrent first writers did not reach verifier creation")
				}
			}
			server := httptest.NewTLSServer(vault)
			t.Cleanup(server.Close)
			a, b := fixtureForServer(t, vault, server), fixtureForServer(t, vault, server)
			a.login(t)
			b.login(t)
			text := "concurrent entry"
			file := writeSecret(t, a.dir, "secret.json", model.Secret{Kind: model.KindText, Title: "Entry", Text: &text})
			passwords := []string{"master-one", "master-two"}
			if samePassword {
				passwords[1] = passwords[0]
			}
			results := make(chan error, 2)
			for i, fixture := range []*cliFixture{a, b} {
				go func(f *cliFixture, password string) {
					args := append(append([]string{}, f.args...), "put", "-file", file)
					results <- Run(context.Background(), args, strings.NewReader(password+"\n"+password+"\n"), io.Discard, io.Discard)
				}(fixture, passwords[i])
			}
			succeeded := 0
			for range 2 {
				err := <-results
				if err == nil {
					succeeded++
				} else if !strings.Contains(err.Error(), "master password") {
					t.Errorf("unexpected first-write error: %v", err)
				}
			}
			want := 1
			if samePassword {
				want = 2
			}
			if succeeded != want || len(vault.records) != want+1 || waiting.Load() != 2 {
				t.Fatalf("succeeded=%d, records=%d, contenders=%d; want %d successful writers and one verifier", succeeded, len(vault.records), waiting.Load(), want)
			}
		})
	}
}

func TestExistingVaultAdoptsVerifierOnlyWithItsCurrentKey(t *testing.T) {
	f := newFixture(t)
	f.login(t)
	key, err := cryptoutil.DeriveKey("master-pass", []byte("1234567890abcdef"))
	if err != nil {
		t.Fatal(err)
	}
	defer clearKey(key)
	id := "11111111111111111111111111111111"
	text := "legacy entry"
	secret := model.Secret{Kind: model.KindText, Title: "Legacy", Text: &text}
	ciphertext, err := cryptoutil.Encrypt(key, id, secret)
	if err != nil {
		t.Fatal(err)
	}
	f.vault.records[id] = model.Record{ID: id, Revision: 1, Ciphertext: ciphertext}
	file := writeSecret(t, f.dir, "secret.json", secret)
	if _, err := f.run(t, "wrong-master\n", "put", "-file", file); err == nil {
		t.Fatal("incorrect legacy key adopted a verifier")
	}
	if _, exists := f.vault.records[model.MasterVerifierID]; exists {
		t.Fatal("incorrect legacy key was persisted")
	}
	if _, err := f.run(t, "master-pass\n", "put", "-file", file); err != nil {
		t.Fatal(err)
	}
	if len(f.vault.records) != 3 {
		t.Fatal("legacy entry, new entry and permanent verifier were not preserved")
	}
}

func TestAuthenticationFailuresAndCacheAfterSyncFailure(t *testing.T) {
	f := newFixture(t)
	for _, input := range []string{"short\n", "account-pass\nother-pass\n", strings.Repeat("x", 5000) + "\n", ""} {
		if _, err := f.run(t, input, "register", "-login", "alice"); err == nil {
			t.Fatalf("accepted invalid password input %q", input)
		}
	}
	f.vault.failAuth = true
	if _, err := f.run(t, "account-pass\n", "login", "-login", "alice"); !errors.Is(err, model.ErrUnauthorized) {
		t.Fatalf("invalid account: %v", err)
	}
	f.vault.failAuth = false
	f.vault.failList = true
	if _, err := f.run(t, "account-pass\n", "login", "-login", "alice"); err == nil || !strings.Contains(err.Error(), "authenticated") {
		t.Fatalf("failed sync: %v", err)
	}
	if _, err := os.Stat(f.statePath); err != nil {
		t.Fatal("session not saved before sync")
	}
	f.vault.failList = false
	f.vault.failLogout = true
	if _, err := f.run(t, "", "logout"); err == nil {
		t.Fatal("logout failure ignored")
	}
	if _, err := os.Stat(f.statePath); err != nil {
		t.Fatal("failed logout removed retryable session")
	}
	f.vault.failLogout = false
	f.vault.unauthorizedLogout = true
	if _, err := f.run(t, "", "logout"); err != nil {
		t.Fatal(err)
	}
}

func TestCommandValidation(t *testing.T) {
	f := newFixture(t)
	f.login(t)
	for _, args := range [][]string{{"register", "-h"}, {"login", "-h"}, {"put", "-h"}, {"get", "-h"}, {"delete", "-h"}} {
		if _, err := f.run(t, "", args...); err != nil {
			t.Errorf("help %v: %v", args, err)
		}
	}
	commands := [][]string{
		{"register"}, {"login", "-login", "alice", "extra"}, {"login", "-unknown"},
		{"logout", "extra"}, {"sync", "extra"}, {"list", "extra"},
		{"put", "extra"}, {"put", "-id", "abc"}, {"put", "-id", "abc", "-revision", "0"}, {"put", "-revision", "1"}, {"put", "-revision", "bad"},
		{"get"}, {"get", "-unknown"}, {"delete"}, {"delete", "-revision", "-1", "abc"}, {"delete", "-unknown"},
	}
	for _, args := range commands {
		if _, err := f.run(t, "", args...); err == nil {
			t.Errorf("accepted %v", args)
		}
	}
	if _, err := f.run(t, "", "put", "-file", filepath.Join(f.dir, "missing")); err == nil {
		t.Fatal("missing secret input accepted")
	}
	bad := filepath.Join(f.dir, "bad.json")
	os.WriteFile(bad, []byte(`{"kind":"unknown"}`), 0600)
	if _, err := f.run(t, "", "put", "-file", bad); err == nil {
		t.Fatal("invalid secret accepted")
	}
	os.WriteFile(bad, []byte(`{broken`), 0600)
	if _, err := f.run(t, "", "put", "-file", bad); err == nil {
		t.Fatal("broken JSON accepted")
	}
	if _, err := f.run(t, "master-pass\nother-pass\n{}", "put"); err == nil {
		t.Fatal("master confirmation mismatch accepted")
	}
	if _, err := f.run(t, "master-pass\nmaster-pass\n{broken", "put"); err == nil {
		t.Fatal("broken stdin accepted")
	}
	if _, err := f.run(t, "master-pass\nmaster-pass\n{}", "put"); err == nil {
		t.Fatal("invalid stdin accepted")
	}
	if _, err := f.run(t, "", "delete", "missing"); !errors.Is(err, model.ErrNotFound) {
		t.Fatalf("missing delete: %v", err)
	}
	s, err := loadState(config{ServerURL: f.args[1], StateFile: f.statePath})
	if err != nil {
		t.Fatal(err)
	}
	s.ExpiresAt = time.Now().Add(-time.Hour)
	if err := saveState(f.statePath, s); err != nil {
		t.Fatal(err)
	}
	if _, err := f.run(t, "", "sync"); err == nil || !strings.Contains(err.Error(), "expired") {
		t.Fatalf("expiry: %v", err)
	}
}

func TestUsageAndVersion(t *testing.T) {
	for _, args := range [][]string{nil, {"help"}, {"-h"}, {"version"}, {"-state-file", "test", "version"}, {"-state-file", "test", "help"}} {
		var out, diagnostics bytes.Buffer
		if err := Run(context.Background(), args, strings.NewReader(""), &out, &diagnostics); err != nil {
			t.Fatalf("%v: %v", args, err)
		}
		if out.Len()+diagnostics.Len() == 0 {
			t.Fatalf("no output for %v", args)
		}
	}
	for _, args := range [][]string{{"-unknown"}, {"-state-file", "test"}, {"no-such-command"}, {"-server-url", "http://localhost", "sync"}} {
		if err := Run(context.Background(), args, strings.NewReader(""), io.Discard, io.Discard); err == nil {
			t.Fatalf("accepted %v", args)
		}
	}
	if err := Run(context.Background(), nil, nil, io.Discard, io.Discard); err == nil {
		t.Fatal("nil input accepted")
	}
}
