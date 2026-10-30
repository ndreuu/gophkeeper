package client

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ndreuu/go-gophkeeper/internal/model"
)

const testID = "0123456789abcdef0123456789abcdef"

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func testClient(t *testing.T, fn roundTripFunc) *Client {
	t.Helper()
	c, err := New("https://vault.example", "")
	if err != nil {
		t.Fatal(err)
	}
	c.httpClient.Transport = fn
	return c
}

func response(code int, body string) *http.Response {
	return &http.Response{StatusCode: code, Status: fmt.Sprintf("%d %s", code, http.StatusText(code)), Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body))}
}

func TestNew(t *testing.T) {
	for _, address := range []string{"", "http://localhost", "https:", ":bad", "https://user:password@example.com", "https://example.com?q=a", "https://example.com#fragment"} {
		if _, err := New(address, ""); !errors.Is(err, model.ErrInvalid) {
			t.Errorf("%q accepted: %v", address, err)
		}
	}
	c, err := New("https://example.com/base/", "")
	if err != nil {
		t.Fatal(err)
	}
	if c.httpClient.Timeout != 30*time.Second {
		t.Fatalf("timeout = %v", c.httpClient.Timeout)
	}
	transport := c.httpClient.Transport.(*http.Transport)
	if transport.TLSClientConfig.InsecureSkipVerify || transport.TLSClientConfig.MinVersion == 0 {
		t.Fatal("unverified TLS")
	}
	if err := c.httpClient.CheckRedirect(nil, nil); err != http.ErrUseLastResponse {
		t.Fatalf("redirect policy: %v", err)
	}
	if _, err := New("https://example.com", filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Fatal("missing CA accepted")
	}
	badCA := filepath.Join(t.TempDir(), "bad.pem")
	if err := os.WriteFile(badCA, []byte("not a certificate"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := New("https://example.com", badCA); !errors.Is(err, model.ErrInvalid) {
		t.Fatalf("invalid CA accepted: %v", err)
	}
}

func TestVerifiedTLS(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"token":"session","vault_salt":"MDEyMzQ1Njc4OWFiY2RlZg=="}`)
	}))
	defer server.Close()
	untrusted, err := New(server.URL, "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := untrusted.Login(context.Background(), model.Credentials{Login: "alice", Password: "password"}); err == nil {
		t.Fatal("self-signed certificate trusted without explicit CA")
	}
	caFile := filepath.Join(t.TempDir(), "server-ca.pem")
	if err := os.WriteFile(caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	trusted, err := New(server.URL, caFile)
	if err != nil {
		t.Fatal(err)
	}
	auth, err := trusted.Login(context.Background(), model.Credentials{Login: "alice", Password: "password"})
	if err != nil {
		t.Fatal(err)
	}
	if auth.Token != "session" || string(auth.VaultSalt) != "0123456789abcdef" {
		t.Fatalf("unexpected auth result: %#v", auth)
	}
}

func TestCredentialsRequests(t *testing.T) {
	credentials := model.Credentials{Login: "alice", Password: "secret password"}
	auth := model.AuthResult{Token: "session", ExpiresAt: time.Now().UTC().Truncate(time.Second), VaultSalt: []byte("0123456789abcdef")}
	for _, name := range []string{"register", "login"} {
		t.Run(name, func(t *testing.T) {
			c := testClient(t, func(r *http.Request) (*http.Response, error) {
				if r.Method != http.MethodPost || r.URL.Path != "/api/v1/"+name || r.Header.Get("Authorization") != "" || r.Header.Get("Content-Type") != "application/json" {
					t.Fatalf("unexpected request: %v %v %v", r.Method, r.URL, r.Header)
				}
				var got model.Credentials
				if err := json.NewDecoder(r.Body).Decode(&got); err != nil || got != credentials {
					t.Fatalf("credentials: %#v %v", got, err)
				}
				data, _ := json.Marshal(auth)
				status := http.StatusOK
				if name == "register" {
					status = http.StatusCreated
				}
				return response(status, string(data)), nil
			})
			var got model.AuthResult
			var err error
			if name == "register" {
				got, err = c.Register(context.Background(), credentials)
			} else {
				got, err = c.Login(context.Background(), credentials)
			}
			if err != nil || !reflect.DeepEqual(got, auth) {
				t.Fatalf("auth: %#v %v", got, err)
			}
			if c.token != "" {
				t.Fatal("authentication unexpectedly replaced client token")
			}
		})
	}
}

func TestEntryRequests(t *testing.T) {
	record := model.Record{ID: testID, Revision: 2, Ciphertext: []byte("encrypted"), UpdatedAt: time.Now().UTC().Truncate(time.Second)}
	data, _ := json.Marshal(record)
	ctx := context.Background()
	c := testClient(t, func(r *http.Request) (*http.Response, error) {
		if r.Header.Get("Authorization") != "Bearer session" {
			t.Fatalf("missing authentication: %v", r.Header)
		}
		if r.Header.Get("Accept") != "application/json" {
			t.Fatal("missing JSON accept header")
		}
		switch r.Method + " " + r.URL.Path {
		case "GET /api/v1/entries":
			return response(http.StatusOK, `{"entries":[`+string(data)+`]}`), nil
		case "GET /api/v1/entries/" + testID:
			return response(http.StatusOK, string(data)), nil
		case "PUT /api/v1/entries/" + testID:
			var put model.PutRequest
			if err := json.NewDecoder(r.Body).Decode(&put); err != nil || put.ExpectedRevision != 1 || string(put.Ciphertext) != "encrypted" {
				t.Fatalf("put: %#v %v", put, err)
			}
			return response(http.StatusOK, string(data)), nil
		case "DELETE /api/v1/entries/" + testID:
			if r.URL.Query().Get("revision") != "2" {
				t.Fatalf("delete revision: %v", r.URL)
			}
			return response(http.StatusNoContent, ""), nil
		case "POST /api/v1/logout":
			return response(http.StatusNoContent, ""), nil
		default:
			t.Fatalf("unexpected request: %v %v", r.Method, r.URL)
			return nil, errors.New("unreachable")
		}
	})
	c.SetToken("session")
	entries, err := c.List(ctx)
	if err != nil || !reflect.DeepEqual(entries, []model.Record{record}) {
		t.Fatalf("list: %#v %v", entries, err)
	}
	got, err := c.Get(ctx, testID)
	if err != nil || !reflect.DeepEqual(got, record) {
		t.Fatalf("get: %#v %v", got, err)
	}
	got, err = c.Put(ctx, testID, model.PutRequest{ExpectedRevision: 1, Ciphertext: []byte("encrypted")})
	if err != nil || !reflect.DeepEqual(got, record) {
		t.Fatalf("put: %#v %v", got, err)
	}
	if err := c.Delete(ctx, testID, 2); err != nil {
		t.Fatal(err)
	}
	if err := c.Logout(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := c.List(ctx); !errors.Is(err, model.ErrUnauthorized) {
		t.Fatalf("logout did not clear token: %v", err)
	}
}

func TestClientRejectsInvalidIDs(t *testing.T) {
	c := testClient(t, func(*http.Request) (*http.Response, error) {
		t.Fatal("invalid request reached server")
		return nil, nil
	})
	for _, id := range []string{"", "../escape", strings.Repeat("Z", 32), strings.Repeat("A", 32)} {
		if _, err := c.Get(context.Background(), id); !errors.Is(err, model.ErrInvalid) {
			t.Fatalf("get: %v", err)
		}
		if _, err := c.Put(context.Background(), id, model.PutRequest{}); !errors.Is(err, model.ErrInvalid) {
			t.Fatalf("put: %v", err)
		}
		if err := c.Delete(context.Background(), id, 1); !errors.Is(err, model.ErrInvalid) {
			t.Fatalf("delete: %v", err)
		}
	}
}

func TestHTTPStatusMapping(t *testing.T) {
	for _, tc := range []struct {
		status int
		want   error
	}{
		{400, model.ErrInvalid}, {401, model.ErrUnauthorized}, {403, model.ErrUnauthorized}, {404, model.ErrNotFound}, {409, model.ErrConflict}, {413, model.ErrCapacity}, {500, nil}, {302, nil},
	} {
		t.Run(http.StatusText(tc.status), func(t *testing.T) {
			c := testClient(t, func(*http.Request) (*http.Response, error) {
				return response(tc.status, `{"error":"private secret"}`), nil
			})
			c.SetToken("session")
			_, err := c.Get(context.Background(), testID)
			if err == nil || tc.want != nil && !errors.Is(err, tc.want) {
				t.Fatalf("status %d: %v", tc.status, err)
			}
			if strings.Contains(err.Error(), "private secret") {
				t.Fatal("error response leaked into terminal output")
			}
			if err := c.Logout(context.Background()); err == nil || c.token != "session" {
				t.Fatalf("failed logout cleared session: %v", err)
			}
		})
	}
}

type failingReader struct{}

func (failingReader) Read([]byte) (int, error) { return 0, errors.New("read failure") }
func (failingReader) Close() error             { return nil }

func TestTransportAndDecodeErrors(t *testing.T) {
	ctx := context.Background()
	for _, tc := range []struct {
		name     string
		response *http.Response
		err      error
	}{
		{"transport", nil, errors.New("offline")},
		{"read", &http.Response{StatusCode: 200, Body: failingReader{}}, nil},
		{"decode", response(200, "not JSON"), nil},
		{"extra JSON", response(200, `{"entries":[]} {}`), nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := testClient(t, func(*http.Request) (*http.Response, error) { return tc.response, tc.err })
			c.SetToken("session")
			if _, err := c.List(ctx); err == nil {
				t.Fatal("invalid response accepted")
			}
		})
	}
	c := testClient(t, func(*http.Request) (*http.Response, error) { t.Fatal("malformed request was sent"); return nil, nil })
	if err := c.request(ctx, "GET", "/", nil, make(chan int), nil, 200, false); err == nil {
		t.Fatal("non-JSON request accepted")
	}
	if err := c.request(ctx, "bad method", "/", nil, nil, nil, 200, false); err == nil {
		t.Fatal("invalid method accepted")
	}
}

func TestContextCancellation(t *testing.T) {
	c, err := New("https://example.test", "")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := c.Login(ctx, model.Credentials{}); !errors.Is(err, context.Canceled) {
		t.Fatalf("context cancellation lost: %v", err)
	}
}

func TestBasePath(t *testing.T) {
	c := testClient(t, func(r *http.Request) (*http.Response, error) {
		if r.URL.String() != "https://vault.example/prefix/api/v1/entries" {
			t.Fatalf("base path ignored: %s", r.URL)
		}
		return response(200, `{"entries":[]}`), nil
	})
	c.baseURL.Path = "/prefix/"
	c.SetToken("session")
	if _, err := c.List(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestConcurrentSessionReplacement(t *testing.T) {
	c := testClient(t, func(r *http.Request) (*http.Response, error) {
		if !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer token-") {
			t.Error("request observed a partial session token")
		}
		return response(200, `{"entries":[]}`), nil
	})
	c.SetToken("token-initial")
	var wg sync.WaitGroup
	for i := range 16 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c.SetToken(fmt.Sprintf("token-%d", i))
			if _, err := c.List(context.Background()); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
}
