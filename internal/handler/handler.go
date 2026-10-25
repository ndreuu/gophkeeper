package handler

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
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
	r := gin.New()
	a := api{service: service, log: log}
	r.Use(func(c *gin.Context) {
		c.Header("Cache-Control", "no-store")
		c.Header("X-Content-Type-Options", "nosniff")
		start := time.Now()
		c.Next()
		log.Info("HTTP request", zap.String("method", c.Request.Method), zap.String("route", c.FullPath()), zap.Int("status", c.Writer.Status()), zap.Duration("duration", time.Since(start)))
	})
	r.Use(gin.CustomRecoveryWithWriter(io.Discard, func(c *gin.Context, _ any) {
		log.Error("request panicked")
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
	}))
	r.GET("/healthz", func(c *gin.Context) {
		if err := ping(c.Request.Context()); err != nil {
			c.JSON(http.StatusServiceUnavailable, gin.H{"error": "storage unavailable"})
			return
		}
		c.Status(http.StatusOK)
	})
	v1 := r.Group("/api/v1")
	v1.POST("/register", a.credentials(true))
	v1.POST("/login", a.credentials(false))
	private := v1.Group("")
	private.Use(a.authorize)
	private.POST("/logout", func(c *gin.Context) {
		if err := service.Logout(c.Request.Context(), c.GetString("token")); err != nil {
			a.fail(c, err)
			return
		}
		c.Status(http.StatusNoContent)
	})
	private.GET("/entries", func(c *gin.Context) {
		entries, err := service.List(c.Request.Context(), c.GetString("owner"))
		if err != nil {
			a.fail(c, err)
			return
		}
		if entries == nil {
			entries = []model.Record{}
		}
		c.JSON(http.StatusOK, gin.H{"entries": entries})
	})
	private.GET("/entries/:id", func(c *gin.Context) {
		entry, err := service.Get(c.Request.Context(), c.GetString("owner"), c.Param("id"))
		if err != nil {
			a.fail(c, err)
			return
		}
		c.JSON(http.StatusOK, entry)
	})
	private.PUT("/entries/:id", func(c *gin.Context) {
		var req model.PutRequest
		if !a.decode(c, &req, int64((model.MaxCiphertextSize+2)/3*4+1024)) {
			return
		}
		entry, err := service.Put(c.Request.Context(), c.GetString("owner"), c.Param("id"), req)
		if err != nil {
			a.fail(c, err)
			return
		}
		c.JSON(http.StatusOK, entry)
	})
	private.DELETE("/entries/:id", func(c *gin.Context) {
		revision, err := strconv.ParseInt(c.Query("revision"), 10, 64)
		if err != nil || revision <= 0 {
			a.fail(c, model.ErrInvalid)
			return
		}
		if err = service.Delete(c.Request.Context(), c.GetString("owner"), c.Param("id"), revision); err != nil {
			a.fail(c, err)
			return
		}
		c.Status(http.StatusNoContent)
	})
	return r
}

func (a api) credentials(register bool) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req model.Credentials
		if !a.decode(c, &req, 8192) {
			return
		}
		var result model.AuthResult
		var err error
		status := http.StatusOK
		if register {
			result, err = a.service.Register(c.Request.Context(), req)
			status = http.StatusCreated
		} else {
			result, err = a.service.Login(c.Request.Context(), req)
		}
		if err != nil {
			a.fail(c, err)
			return
		}
		c.JSON(status, result)
	}
}

func (a api) authorize(c *gin.Context) {
	scheme, token, ok := strings.Cut(c.GetHeader("Authorization"), " ")
	if !ok || !strings.EqualFold(scheme, "Bearer") || token == "" || strings.ContainsAny(token, " \t\r\n") {
		a.fail(c, model.ErrUnauthorized)
		return
	}
	owner, err := a.service.Authenticate(c.Request.Context(), token)
	if err != nil {
		a.fail(c, err)
		return
	}
	c.Set("owner", owner)
	c.Set("token", token)
	c.Next()
}

func (a api) decode(c *gin.Context, dest any, limit int64) bool {
	if contentType := c.ContentType(); contentType != "application/json" {
		c.AbortWithStatusJSON(http.StatusUnsupportedMediaType, gin.H{"error": "application/json required"})
		return false
	}
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, limit)
	decoder := json.NewDecoder(c.Request.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(dest); err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			c.AbortWithStatusJSON(http.StatusRequestEntityTooLarge, gin.H{"error": "request too large"})
		} else {
			a.fail(c, model.ErrInvalid)
		}
		return false
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		a.fail(c, model.ErrInvalid)
		return false
	}
	return true
}

func (a api) fail(c *gin.Context, err error) {
	status, message := http.StatusInternalServerError, "internal server error"
	switch {
	case errors.Is(err, model.ErrInvalid):
		status, message = http.StatusBadRequest, "invalid input"
	case errors.Is(err, model.ErrUnauthorized):
		status, message = http.StatusUnauthorized, "authentication required"
		c.Header("WWW-Authenticate", "Bearer")
	case errors.Is(err, model.ErrNotFound):
		status, message = http.StatusNotFound, "entry not found"
	case errors.Is(err, model.ErrConflict):
		status, message = http.StatusConflict, "login already exists or entry revision changed"
	case errors.Is(err, model.ErrCapacity):
		status, message = http.StatusRequestEntityTooLarge, "vault capacity exceeded (64 MiB or 10000 encrypted entries)"
	default:
		a.log.Error("service request failed", zap.String("route", c.FullPath()))
	}
	c.AbortWithStatusJSON(status, gin.H{"error": message})
}
