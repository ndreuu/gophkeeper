package client

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ndreuu/go-gophkeeper/internal/model"
)

const maxResponseSize = 128 * 1024 * 1024

type Client struct {
	baseURL    *url.URL
	httpClient *http.Client
	mu         sync.RWMutex
	token      string
}

// New creates a client with verified TLS 1.2 or newer. caFile optionally adds
// PEM-encoded CA certificates to the system trust store for a private server.
// Plain HTTP, embedded URL credentials and redirects are rejected.
func New(serverURL, caFile string) (*Client, error) {
	u, err := url.Parse(serverURL)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return nil, fmt.Errorf("server URL must be an HTTPS URL without credentials, query or fragment: %w", model.ErrInvalid)
	}
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12}
	if caFile != "" {
		pem, err := os.ReadFile(caFile)
		if err != nil {
			return nil, fmt.Errorf("read server CA: %w", err)
		}
		roots, err := x509.SystemCertPool()
		if err != nil {
			roots = x509.NewCertPool()
		}
		if !roots.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("server CA contains no valid certificates: %w", model.ErrInvalid)
		}
		tlsConfig.RootCAs = roots
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = tlsConfig
	return &Client{baseURL: u, httpClient: &http.Client{
		Timeout:       30 * time.Second,
		Transport:     transport,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}}, nil
}

// SetToken sets the bearer token used by subsequent authenticated requests.
func (c *Client) SetToken(token string) {
	c.mu.Lock()
	c.token = token
	c.mu.Unlock()
}

// Register creates an account and returns its session and public vault salt.
// Call SetToken to use the returned session on this client.
func (c *Client) Register(ctx context.Context, credentials model.Credentials) (model.AuthResult, error) {
	var result model.AuthResult
	err := c.request(ctx, http.MethodPost, "/api/v1/register", nil, credentials, &result, http.StatusCreated, false)
	return result, err
}

// Login authenticates account credentials and returns a fresh session.
// Call SetToken to use the returned session on this client.
func (c *Client) Login(ctx context.Context, credentials model.Credentials) (model.AuthResult, error) {
	var result model.AuthResult
	err := c.request(ctx, http.MethodPost, "/api/v1/login", nil, credentials, &result, http.StatusOK, false)
	return result, err
}

// Logout revokes the current session and clears its token after success.
func (c *Client) Logout(ctx context.Context) error {
	if err := c.request(ctx, http.MethodPost, "/api/v1/logout", nil, nil, nil, http.StatusNoContent, true); err != nil {
		return err
	}
	c.SetToken("")
	return nil
}

// List fetches the owner's current encrypted snapshot, including revisions.
func (c *Client) List(ctx context.Context) ([]model.Record, error) {
	var result struct {
		Entries []model.Record `json:"entries"`
	}
	err := c.request(ctx, http.MethodGet, "/api/v1/entries", nil, nil, &result, http.StatusOK, true)
	return result.Entries, err
}

// Get fetches one encrypted entry belonging to the authenticated owner.
func (c *Client) Get(ctx context.Context, id string) (model.Record, error) {
	if !model.ValidID(id) {
		return model.Record{}, invalidID()
	}
	var result model.Record
	err := c.request(ctx, http.MethodGet, "/api/v1/entries/"+id, nil, nil, &result, http.StatusOK, true)
	return result, err
}

// Put creates or replaces an encrypted entry using optimistic revision checks.
// A conflict preserves model.ErrConflict so callers can resolve stale edits.
func (c *Client) Put(ctx context.Context, id string, request model.PutRequest) (model.Record, error) {
	if !model.ValidID(id) {
		return model.Record{}, invalidID()
	}
	var result model.Record
	err := c.request(ctx, http.MethodPut, "/api/v1/entries/"+id, nil, request, &result, http.StatusOK, true)
	return result, err
}

// Delete removes an entry only if its current revision matches revision.
func (c *Client) Delete(ctx context.Context, id string, revision int64) error {
	if !model.ValidID(id) {
		return invalidID()
	}
	return c.request(ctx, http.MethodDelete, "/api/v1/entries/"+id, url.Values{"revision": {strconv.FormatInt(revision, 10)}}, nil, nil, http.StatusNoContent, true)
}

func (c *Client) request(ctx context.Context, method, path string, query url.Values, payload, result any, success int, authenticated bool) error {
	var body io.Reader
	if payload != nil {
		encoded, err := json.Marshal(payload)
		if err != nil {
			return fmt.Errorf("encode request: %w", err)
		}
		body = bytes.NewReader(encoded)
	}
	u := *c.baseURL
	u.Path = strings.TrimRight(u.Path, "/") + path
	u.RawPath = ""
	u.RawQuery = query.Encode()
	req, err := http.NewRequestWithContext(ctx, method, u.String(), body)
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if authenticated {
		c.mu.RLock()
		token := c.token
		c.mu.RUnlock()
		if token == "" {
			return model.ErrUnauthorized
		}
		req.Header.Set("Authorization", "Bearer "+token)
	}
	response, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("contact server: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != success {
		return responseError(response)
	}
	if result == nil {
		return nil
	}
	limited := io.LimitReader(response.Body, maxResponseSize+1)
	data, err := io.ReadAll(limited)
	if err != nil {
		return fmt.Errorf("read server response: %w", err)
	}
	if len(data) > maxResponseSize {
		return fmt.Errorf("server response exceeds 128 MiB")
	}
	if err := json.Unmarshal(data, result); err != nil {
		return fmt.Errorf("decode server response: %w", err)
	}
	return nil
}

func responseError(response *http.Response) error {
	var cause error
	switch response.StatusCode {
	case http.StatusBadRequest:
		cause = model.ErrInvalid
	case http.StatusUnauthorized, http.StatusForbidden:
		cause = model.ErrUnauthorized
	case http.StatusNotFound:
		cause = model.ErrNotFound
	case http.StatusConflict:
		cause = model.ErrConflict
	case http.StatusRequestEntityTooLarge:
		cause = model.ErrCapacity
	}
	if cause != nil {
		return fmt.Errorf("server returned %s: %w", response.Status, cause)
	}
	return fmt.Errorf("server returned %s", response.Status)
}

func invalidID() error {
	return fmt.Errorf("entry ID must contain 32 lowercase hex characters: %w", model.ErrInvalid)
}
