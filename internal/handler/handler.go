package handler

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/ndreuu/go-gophkeeper/internal/model"
	"go.uber.org/zap"
)

type Service interface {
	Register(context.Context, model.Credentials) (model.AuthResult, error)
	Login(context.Context, model.Credentials) (model.AuthResult, error)
	Authenticate(context.Context, string) (string, error)
	Logout(context.Context, string) error
	List(context.Context, string) ([]model.Record, error)
	Get(context.Context, string, string) (model.Record, error)
	Put(context.Context, string, string, model.PutRequest) (model.Record, error)
	Delete(context.Context, string, string, int64) error
}

type api struct {
	service Service
	log     *zap.Logger
}

// New creates a router. ping checks backing storage; logs contain routes/statuses, never secrets.
func New(service Service, ping func(context.Context) error, log *zap.Logger) http.Handler {
	mux := http.NewServeMux()
	a := api{service: service, log: log}
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		if err := ping(r.Context()); err != nil {
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "storage unavailable"})
			return
		}
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("POST /api/v1/register", a.credentials(true))
	mux.HandleFunc("POST /api/v1/login", a.credentials(false))
	mux.HandleFunc("POST /api/v1/logout", a.authorize(func(w http.ResponseWriter, r *http.Request, _, token string) {
		if err := service.Logout(r.Context(), token); err != nil {
			a.fail(w, r, err)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	mux.HandleFunc("GET /api/v1/entries", a.authorize(func(w http.ResponseWriter, r *http.Request, owner, _ string) {
		entries, err := service.List(r.Context(), owner)
		if err != nil {
			a.fail(w, r, err)
			return
		}
		if entries == nil {
			entries = []model.Record{}
		}
		writeJSON(w, http.StatusOK, map[string][]model.Record{"entries": entries})
	}))
	mux.HandleFunc("GET /api/v1/entries/{id}", a.authorize(func(w http.ResponseWriter, r *http.Request, owner, _ string) {
		entry, err := service.Get(r.Context(), owner, r.PathValue("id"))
		if err != nil {
			a.fail(w, r, err)
			return
		}
		writeJSON(w, http.StatusOK, entry)
	}))
	mux.HandleFunc("PUT /api/v1/entries/{id}", a.authorize(func(w http.ResponseWriter, r *http.Request, owner, _ string) {
		var req model.PutRequest
		if !a.decode(w, r, &req, int64((model.MaxCiphertextSize+2)/3*4+1024)) {
			return
		}
		entry, err := service.Put(r.Context(), owner, r.PathValue("id"), req)
		if err != nil {
			a.fail(w, r, err)
			return
		}
		writeJSON(w, http.StatusOK, entry)
	}))
	mux.HandleFunc("DELETE /api/v1/entries/{id}", a.authorize(func(w http.ResponseWriter, r *http.Request, owner, _ string) {
		revision, err := strconv.ParseInt(r.URL.Query().Get("revision"), 10, 64)
		if err != nil || revision <= 0 {
			a.fail(w, r, model.ErrInvalid)
			return
		}
		if err = service.Delete(r.Context(), owner, r.PathValue("id"), revision); err != nil {
			a.fail(w, r, err)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		response := &responseWriter{ResponseWriter: w}
		start := time.Now()
		defer func() {
			if recover() != nil {
				log.Error("request panicked")
				if response.status == 0 {
					writeJSON(response, http.StatusInternalServerError, map[string]string{"error": "internal server error"})
				}
			}
			_, route, _ := strings.Cut(r.Pattern, " ")
			log.Info("HTTP request", zap.String("method", r.Method), zap.String("route", route), zap.Int("status", response.status), zap.Duration("duration", time.Since(start)))
		}()
		mux.ServeHTTP(response, r)
	})
}

func (a api) credentials(register bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req model.Credentials
		if !a.decode(w, r, &req, 8192) {
			return
		}
		var result model.AuthResult
		var err error
		status := http.StatusOK
		if register {
			result, err = a.service.Register(r.Context(), req)
			status = http.StatusCreated
		} else {
			result, err = a.service.Login(r.Context(), req)
		}
		if err != nil {
			a.fail(w, r, err)
			return
		}
		writeJSON(w, status, result)
	}
}

func (a api) authorize(next func(http.ResponseWriter, *http.Request, string, string)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		scheme, token, ok := strings.Cut(r.Header.Get("Authorization"), " ")
		if !ok || !strings.EqualFold(scheme, "Bearer") || token == "" || strings.ContainsAny(token, " \t\r\n") {
			a.fail(w, r, model.ErrUnauthorized)
			return
		}
		owner, err := a.service.Authenticate(r.Context(), token)
		if err != nil {
			a.fail(w, r, err)
			return
		}
		next(w, r, owner, token)
	}
}

func (a api) decode(w http.ResponseWriter, r *http.Request, dest any, limit int64) bool {
	if contentType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type")); err != nil || contentType != "application/json" {
		writeJSON(w, http.StatusUnsupportedMediaType, map[string]string{"error": "application/json required"})
		return false
	}
	r.Body = http.MaxBytesReader(w, r.Body, limit)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(dest); err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			writeJSON(w, http.StatusRequestEntityTooLarge, map[string]string{"error": "request too large"})
		} else {
			a.fail(w, r, model.ErrInvalid)
		}
		return false
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		a.fail(w, r, model.ErrInvalid)
		return false
	}
	return true
}

func (a api) fail(w http.ResponseWriter, r *http.Request, err error) {
	status, message := http.StatusInternalServerError, "internal server error"
	switch {
	case errors.Is(err, model.ErrInvalid):
		status, message = http.StatusBadRequest, "invalid input"
	case errors.Is(err, model.ErrUnauthorized):
		status, message = http.StatusUnauthorized, "authentication required"
		w.Header().Set("WWW-Authenticate", "Bearer")
	case errors.Is(err, model.ErrNotFound):
		status, message = http.StatusNotFound, "entry not found"
	case errors.Is(err, model.ErrConflict):
		status, message = http.StatusConflict, "login already exists or entry revision changed"
	case errors.Is(err, model.ErrCapacity):
		status, message = http.StatusRequestEntityTooLarge, "vault capacity exceeded (64 MiB or 10000 encrypted entries)"
	default:
		_, route, _ := strings.Cut(r.Pattern, " ")
		a.log.Error("service request failed", zap.String("route", route))
	}
	writeJSON(w, status, map[string]string{"error": message})
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

type responseWriter struct {
	http.ResponseWriter
	status int
}

func (w *responseWriter) WriteHeader(status int) {
	if w.status != 0 {
		return
	}
	w.status = status
	w.ResponseWriter.WriteHeader(status)
}

func (w *responseWriter) Write(body []byte) (int, error) {
	if w.status == 0 {
		w.WriteHeader(http.StatusOK)
	}
	return w.ResponseWriter.Write(body)
}
