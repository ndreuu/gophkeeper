package repository

import (
	"context"
	"database/sql"
	sqldriver "database/sql/driver"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/golang-migrate/migrate/v4"
	migratepostgres "github.com/golang-migrate/migrate/v4/database/postgres"
	"github.com/golang-migrate/migrate/v4/source/iofs"
	"github.com/lib/pq"
	"github.com/ndreuu/go-gophkeeper/internal/model"
	"github.com/ndreuu/go-gophkeeper/migrations"
)

type Postgres struct {
	db *sql.DB
}

// New opens PostgreSQL, verifies connectivity and applies embedded migrations.
func New(ctx context.Context, dsn string) (*Postgres, error) {
	if dsn == "" {
		return nil, fmt.Errorf("database DSN is required")
	}
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		return nil, &startupError{operation: "open PostgreSQL", cause: err}
	}
	db.SetMaxOpenConns(25)
	db.SetMaxIdleConns(5)
	db.SetConnMaxLifetime(5 * time.Minute)
	db.SetConnMaxIdleTime(5 * time.Minute)
	startup, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	if err := db.PingContext(startup); err != nil {
		_ = db.Close()
		return nil, &startupError{operation: "ping PostgreSQL", cause: err}
	}
	if err := migrateDatabase(startup, db); err != nil {
		_ = db.Close()
		return nil, &startupError{operation: "migrate PostgreSQL", cause: err}
	}
	return &Postgres{db: db}, nil
}

type startupError struct {
	operation string
	cause     error
}

func (e *startupError) Error() string { return e.operation + ": database initialization failed" }
func (e *startupError) Unwrap() error { return e.cause }

func migrateDatabase(ctx context.Context, db *sql.DB) error {
	source, err := iofs.New(migrations.Files, ".")
	if err != nil {
		return err
	}
	defer source.Close()
	connection, err := db.Conn(ctx)
	if err != nil {
		return err
	}
	defer connection.Close()
	timeout := 30 * time.Second
	if deadline, ok := ctx.Deadline(); ok {
		timeout = min(timeout, time.Until(deadline))
	}
	_, err = connection.ExecContext(ctx, `SELECT set_config('statement_timeout', $1, false)`,
		strconv.FormatInt(max(1, timeout.Milliseconds()), 10))
	if err != nil {
		_ = connection.Raw(func(any) error { return sqldriver.ErrBadConn })
		return err
	}
	defer func() {
		cleanup, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		if _, err := connection.ExecContext(cleanup, `RESET statement_timeout`); err != nil {
			_ = connection.Raw(func(any) error { return sqldriver.ErrBadConn })
		}
	}()
	driver, err := migratepostgres.WithConnection(ctx, connection, &migratepostgres.Config{
		StatementTimeout: timeout,
	})
	if err != nil {
		return err
	}
	migrator, err := migrate.NewWithInstance("iofs", source, "postgres", driver)
	if err != nil {
		return err
	}
	migrator.LockTimeout = timeout + time.Second
	if err := migrator.Up(); err != nil && !errors.Is(err, migrate.ErrNoChange) {
		return err
	}
	return nil
}

// Close releases the database connection pool.
func (p *Postgres) Close() error { return p.db.Close() }

// Ping checks database connectivity within the caller's context.
func (p *Postgres) Ping(ctx context.Context) error { return p.db.PingContext(ctx) }

// CreateUser inserts a password hash and public salt, reporting duplicate logins as conflicts.
func (p *Postgres) CreateUser(ctx context.Context, user model.User) error {
	_, err := p.db.ExecContext(ctx,
		`INSERT INTO users (id, login, password_hash, vault_salt) VALUES ($1, $2, $3, $4)`,
		user.ID, user.Login, user.PasswordHash, user.VaultSalt)
	return databaseError("create user", err)
}

// FindUser returns credentials for authentication without exposing them through the HTTP API.
func (p *Postgres) FindUser(ctx context.Context, login string) (model.User, error) {
	var user model.User
	err := p.db.QueryRowContext(ctx,
		`SELECT id, login, password_hash, vault_salt FROM users WHERE login = $1`, login).
		Scan(&user.ID, &user.Login, &user.PasswordHash, &user.VaultSalt)
	return user, databaseError("find user", err)
}

// CreateSession persists a token digest and expiry, never its reusable bearer value.
func (p *Postgres) CreateSession(ctx context.Context, tokenHash []byte, userID string, expiresAt time.Time) error {
	_, err := p.db.ExecContext(ctx,
		`INSERT INTO sessions (token_hash, user_id, expires_at) VALUES ($1, $2, $3)`, tokenHash, userID, expiresAt)
	return databaseError("create session", err)
}

// SessionUser resolves only sessions whose expiry is later than now.
func (p *Postgres) SessionUser(ctx context.Context, tokenHash []byte, now time.Time) (string, error) {
	var userID string
	err := p.db.QueryRowContext(ctx,
		`SELECT user_id FROM sessions WHERE token_hash = $1 AND expires_at > $2`, tokenHash, now).Scan(&userID)
	return userID, databaseError("find session", err)
}

// DeleteSession revokes an existing token and succeeds if it was already revoked.
func (p *Postgres) DeleteSession(ctx context.Context, tokenHash []byte) error {
	_, err := p.db.ExecContext(ctx, `DELETE FROM sessions WHERE token_hash = $1`, tokenHash)
	return databaseError("delete session", err)
}

// ListRecords returns only one owner's encrypted entries, in stable ID order.
func (p *Postgres) ListRecords(ctx context.Context, userID string) ([]model.Record, error) {
	rows, err := p.db.QueryContext(ctx,
		`SELECT id, revision, ciphertext, updated_at FROM records WHERE user_id = $1 ORDER BY id`, userID)
	if err != nil {
		return nil, databaseError("list entries", err)
	}
	defer rows.Close()
	records := []model.Record{}
	for rows.Next() {
		record, err := scanRecord(rows)
		if err != nil {
			return nil, databaseError("scan entry", err)
		}
		records = append(records, record)
	}
	if err := rows.Err(); err != nil {
		return nil, databaseError("read entries", err)
	}
	return records, nil
}

// GetRecord cannot retrieve an entry owned by another account.
func (p *Postgres) GetRecord(ctx context.Context, userID, id string) (model.Record, error) {
	record, err := scanRecord(p.db.QueryRowContext(ctx,
		`SELECT id, revision, ciphertext, updated_at FROM records WHERE user_id = $1 AND id = $2`, userID, id))
	return record, databaseError("get entry", err)
}

// PutRecord atomically creates revision one or updates exactly the expected owner/revision.
// An owner-row lock serializes writers before checking the vault's byte and entry quotas.
func (p *Postgres) PutRecord(ctx context.Context, userID, id string, expected int64, ciphertext []byte) (model.Record, error) {
	tx, err := p.db.BeginTx(ctx, nil)
	if err != nil {
		return model.Record{}, databaseError("begin entry update", err)
	}
	defer tx.Rollback()
	if err := checkCapacity(ctx, tx, userID, id, expected, len(ciphertext)); err != nil {
		return model.Record{}, err
	}
	var record model.Record
	if expected == 0 {
		record, err = scanRecord(tx.QueryRowContext(ctx,
			`INSERT INTO records (user_id, id, revision, ciphertext) VALUES ($1, $2, 1, $3)
			RETURNING id, revision, ciphertext, updated_at`, userID, id, ciphertext))
	} else {
		record, err = scanRecord(tx.QueryRowContext(ctx,
			`UPDATE records SET revision = revision + 1, ciphertext = $4, updated_at = now()
			WHERE user_id = $1 AND id = $2 AND revision = $3
			RETURNING id, revision, ciphertext, updated_at`, userID, id, expected, ciphertext))
	}
	if err != nil {
		return model.Record{}, databaseError("write entry", err)
	}
	if err := tx.Commit(); err != nil {
		return model.Record{}, databaseError("commit entry update", err)
	}
	return record, nil
}

func checkCapacity(ctx context.Context, tx *sql.Tx, userID, id string, expected int64, newSize int) error {
	var owner string
	if err := tx.QueryRowContext(ctx, `SELECT id FROM users WHERE id = $1 FOR UPDATE`, userID).Scan(&owner); err != nil {
		return databaseError("lock entry owner", err)
	}
	var revision, oldSize int64
	err := tx.QueryRowContext(ctx,
		`SELECT revision, octet_length(ciphertext) FROM records WHERE user_id = $1 AND id = $2`, userID, id).
		Scan(&revision, &oldSize)
	if expected == 0 {
		if err == nil {
			return model.ErrConflict
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return databaseError("inspect entry", err)
		}
	} else {
		if err != nil {
			return databaseError("inspect entry", err)
		}
		if revision != expected {
			return model.ErrConflict
		}
	}
	var used, count int64
	if err := tx.QueryRowContext(ctx,
		`SELECT COALESCE(SUM(octet_length(ciphertext)), 0), COUNT(*) FROM records WHERE user_id = $1`, userID).
		Scan(&used, &count); err != nil {
		return databaseError("inspect vault capacity", err)
	}
	if expected == 0 {
		count++
	}
	if count > model.MaxVaultRecords || used-oldSize > model.MaxVaultCiphertextSize-int64(newSize) {
		return model.ErrCapacity
	}
	return nil
}

// DeleteRecord atomically deletes an entry only when owner and revision both match.
func (p *Postgres) DeleteRecord(ctx context.Context, userID, id string, expected int64) error {
	result, err := p.db.ExecContext(ctx,
		`DELETE FROM records WHERE user_id = $1 AND id = $2 AND revision = $3`, userID, id, expected)
	if err != nil {
		return databaseError("delete entry", err)
	}
	count, err := result.RowsAffected()
	if err != nil {
		return databaseError("delete entry result", err)
	}
	if count == 0 {
		return p.revisionError(ctx, userID, id)
	}
	return nil
}

func (p *Postgres) revisionError(ctx context.Context, userID, id string) error {
	var exists bool
	err := p.db.QueryRowContext(ctx,
		`SELECT EXISTS (SELECT 1 FROM records WHERE user_id = $1 AND id = $2)`, userID, id).Scan(&exists)
	if err != nil {
		return databaseError("check entry revision", err)
	}
	if exists {
		return model.ErrConflict
	}
	return model.ErrNotFound
}

func scanRecord(row interface{ Scan(...any) error }) (model.Record, error) {
	var record model.Record
	err := row.Scan(&record.ID, &record.Revision, &record.Ciphertext, &record.UpdatedAt)
	return record, err
}

func databaseError(operation string, err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("%s: %w", operation, model.ErrNotFound)
	}
	var postgresError *pq.Error
	if errors.As(err, &postgresError) && postgresError.Code == "23505" {
		return fmt.Errorf("%s: %w", operation, model.ErrConflict)
	}
	return fmt.Errorf("%s: %w", operation, err)
}
