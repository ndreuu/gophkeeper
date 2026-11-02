package repository

import (
	"context"
	"database/sql"
	"errors"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/lib/pq"
	"github.com/ndreuu/go-gophkeeper/internal/model"
)

const (
	ownerID  = "0123456789abcdef0123456789abcdef"
	recordID = "abcdef0123456789abcdef0123456789"
)

var testTime = time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC)

func mockRepository(t *testing.T) (*Postgres, sqlmock.Sqlmock) {
	t.Helper()
	db, mock, err := sqlmock.New(sqlmock.MonitorPingsOption(true))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Error(err)
		}
		_ = db.Close()
	})
	return &Postgres{db: db}, mock
}

func recordRows(revision int64) *sqlmock.Rows {
	return sqlmock.NewRows([]string{"id", "revision", "ciphertext", "updated_at"}).
		AddRow(recordID, revision, []byte("encrypted-data"), testTime)
}

func expectCapacityLock(mock sqlmock.Sqlmock, previousRevision, previousSize, used, count int64) {
	mock.ExpectBegin()
	mock.ExpectQuery("SELECT id FROM users WHERE id = \\$1 FOR UPDATE").WithArgs(ownerID).
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(ownerID))
	previous := sqlmock.NewRows([]string{"revision", "octet_length"})
	if previousRevision != 0 {
		previous.AddRow(previousRevision, previousSize)
	}
	mock.ExpectQuery("SELECT revision, octet_length\\(ciphertext\\) FROM records WHERE user_id = \\$1 AND id = \\$2").
		WithArgs(ownerID, recordID).WillReturnRows(previous)
	mock.ExpectQuery("SELECT COALESCE\\(SUM\\(octet_length\\(ciphertext\\)\\), 0\\), COUNT\\(\\*\\) FROM records WHERE user_id = \\$1").
		WithArgs(ownerID).WillReturnRows(sqlmock.NewRows([]string{"used", "count"}).AddRow(used, count))
}

func TestAccountAndSessionQueries(t *testing.T) {
	ctx := context.Background()
	repository, mock := mockRepository(t)
	user := model.User{ID: ownerID, Login: "alice", PasswordHash: "argon2-hash", VaultSalt: make([]byte, 16)}
	mock.ExpectExec("INSERT INTO users").WithArgs(user.ID, user.Login, user.PasswordHash, user.VaultSalt).
		WillReturnResult(sqlmock.NewResult(0, 1))
	if err := repository.CreateUser(ctx, user); err != nil {
		t.Fatal(err)
	}
	mock.ExpectQuery("SELECT id, login, password_hash, vault_salt FROM users WHERE login = \\$1").WithArgs(user.Login).
		WillReturnRows(sqlmock.NewRows([]string{"id", "login", "password_hash", "vault_salt"}).
			AddRow(user.ID, user.Login, user.PasswordHash, user.VaultSalt))
	found, err := repository.FindUser(ctx, user.Login)
	if err != nil || found.ID != user.ID || found.PasswordHash != user.PasswordHash || len(found.VaultSalt) != 16 {
		t.Fatalf("find user: %+v %v", found, err)
	}
	hash := make([]byte, 32)
	mock.ExpectExec("INSERT INTO sessions").WithArgs(hash, ownerID, testTime).
		WillReturnResult(sqlmock.NewResult(0, 1))
	if err := repository.CreateSession(ctx, hash, ownerID, testTime); err != nil {
		t.Fatal(err)
	}
	mock.ExpectQuery("SELECT user_id FROM sessions WHERE token_hash = \\$1 AND expires_at > \\$2").
		WithArgs(hash, testTime).WillReturnRows(sqlmock.NewRows([]string{"user_id"}).AddRow(ownerID))
	if id, err := repository.SessionUser(ctx, hash, testTime); err != nil || id != ownerID {
		t.Fatalf("session user: %s %v", id, err)
	}
	mock.ExpectExec("DELETE FROM sessions WHERE token_hash = \\$1").WithArgs(hash).
		WillReturnResult(sqlmock.NewResult(0, 0))
	if err := repository.DeleteSession(ctx, hash); err != nil {
		t.Fatal(err)
	}
	mock.ExpectPing()
	if err := repository.Ping(ctx); err != nil {
		t.Fatal(err)
	}
	mock.ExpectClose()
	if err := repository.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestAccountAndSessionFailures(t *testing.T) {
	ctx := context.Background()
	repository, mock := mockRepository(t)
	problem := errors.New("connection lost")
	mock.ExpectExec("INSERT INTO users").WillReturnError(&pq.Error{Code: "23505", Detail: "sensitive database detail"})
	if err := repository.CreateUser(ctx, model.User{}); !errors.Is(err, model.ErrConflict) || strings.Contains(err.Error(), "sensitive") {
		t.Fatalf("duplicate account mapping: %v", err)
	}
	mock.ExpectQuery("SELECT id, login").WillReturnRows(sqlmock.NewRows([]string{"id", "login", "password_hash", "vault_salt"}))
	if _, err := repository.FindUser(ctx, "nobody"); !errors.Is(err, model.ErrNotFound) {
		t.Fatalf("missing user: %v", err)
	}
	mock.ExpectExec("INSERT INTO sessions").WillReturnError(problem)
	if err := repository.CreateSession(ctx, nil, ownerID, testTime); !errors.Is(err, problem) {
		t.Fatalf("create session error: %v", err)
	}
	mock.ExpectQuery("SELECT user_id FROM sessions").WillReturnRows(sqlmock.NewRows([]string{"user_id"}))
	if _, err := repository.SessionUser(ctx, nil, testTime); !errors.Is(err, model.ErrNotFound) {
		t.Fatalf("missing or expired session: %v", err)
	}
	mock.ExpectExec("DELETE FROM sessions").WillReturnError(problem)
	if err := repository.DeleteSession(ctx, nil); !errors.Is(err, problem) {
		t.Fatalf("delete session error: %v", err)
	}
}

func TestRecordQueriesScopeEveryOperationToOwner(t *testing.T) {
	ctx := context.Background()
	repository, mock := mockRepository(t)
	mock.ExpectQuery("SELECT id, revision, ciphertext, updated_at FROM records WHERE user_id = \\$1 ORDER BY id").
		WithArgs(ownerID).WillReturnRows(recordRows(1)).RowsWillBeClosed()
	listed, err := repository.ListRecords(ctx, ownerID)
	if err != nil || len(listed) != 1 || listed[0].ID != recordID || !listed[0].UpdatedAt.Equal(testTime) {
		t.Fatalf("list entries: %+v %v", listed, err)
	}
	mock.ExpectQuery("SELECT id, revision, ciphertext, updated_at FROM records WHERE user_id = \\$1 AND id = \\$2").
		WithArgs(ownerID, recordID).WillReturnRows(recordRows(1))
	if record, err := repository.GetRecord(ctx, ownerID, recordID); err != nil || record.Revision != 1 {
		t.Fatalf("get entry: %+v %v", record, err)
	}
	data := []byte("encrypted-data")
	expectCapacityLock(mock, 0, 0, 0, 0)
	mock.ExpectQuery("INSERT INTO records .*RETURNING").WithArgs(ownerID, recordID, data).WillReturnRows(recordRows(1))
	mock.ExpectCommit()
	if record, err := repository.PutRecord(ctx, ownerID, recordID, 0, data); err != nil || record.Revision != 1 {
		t.Fatalf("create entry: %+v %v", record, err)
	}
	expectCapacityLock(mock, 1, int64(len(data)), int64(len(data)), 1)
	mock.ExpectQuery("UPDATE records .*WHERE user_id = \\$1 AND id = \\$2 AND revision = \\$3 RETURNING").
		WithArgs(ownerID, recordID, int64(1), data).WillReturnRows(recordRows(2))
	mock.ExpectCommit()
	if record, err := repository.PutRecord(ctx, ownerID, recordID, 1, data); err != nil || record.Revision != 2 {
		t.Fatalf("update entry: %+v %v", record, err)
	}
	mock.ExpectExec("DELETE FROM records WHERE user_id = \\$1 AND id = \\$2 AND revision = \\$3").
		WithArgs(ownerID, recordID, int64(2)).WillReturnResult(sqlmock.NewResult(0, 1))
	if err := repository.DeleteRecord(ctx, ownerID, recordID, 2); err != nil {
		t.Fatal(err)
	}
}

func TestOptimisticRevisionConflictsAndMissingRecords(t *testing.T) {
	ctx := context.Background()
	for _, exists := range []bool{true, false} {
		t.Run(map[bool]string{true: "conflict", false: "missing owner-scoped entry"}[exists], func(t *testing.T) {
			repository, mock := mockRepository(t)
			wanted := model.ErrNotFound
			if exists {
				wanted = model.ErrConflict
			}
			for _, operation := range []string{"update", "delete"} {
				if operation == "update" {
					mock.ExpectBegin()
					mock.ExpectQuery("SELECT id FROM users").WithArgs(ownerID).
						WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(ownerID))
					rows := sqlmock.NewRows([]string{"revision", "size"})
					if exists {
						rows.AddRow(5, 32)
					}
					mock.ExpectQuery("SELECT revision, octet_length").WithArgs(ownerID, recordID).WillReturnRows(rows)
					mock.ExpectRollback()
				} else {
					mock.ExpectExec("DELETE FROM records").WithArgs(ownerID, recordID, int64(4)).
						WillReturnResult(sqlmock.NewResult(0, 0))
					mock.ExpectQuery(regexp.QuoteMeta("SELECT EXISTS (SELECT 1 FROM records WHERE user_id = $1 AND id = $2)")).
						WithArgs(ownerID, recordID).WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(exists))
				}
				var err error
				if operation == "update" {
					_, err = repository.PutRecord(ctx, ownerID, recordID, 4, []byte("ciphertext"))
				} else {
					err = repository.DeleteRecord(ctx, ownerID, recordID, 4)
				}
				if !errors.Is(err, wanted) {
					t.Fatalf("%s error=%v want=%v", operation, err, wanted)
				}
			}
		})
	}
	repository, mock := mockRepository(t)
	expectCapacityLock(mock, 0, 0, 0, 0)
	mock.ExpectQuery("INSERT INTO records").WillReturnError(&pq.Error{Code: "23505"})
	mock.ExpectRollback()
	if _, err := repository.PutRecord(ctx, ownerID, recordID, 0, nil); !errors.Is(err, model.ErrConflict) {
		t.Fatalf("duplicate creation error: %v", err)
	}
}

func TestRecordReadFailuresAndEmptySnapshot(t *testing.T) {
	ctx := context.Background()
	problem := errors.New("read failure")
	t.Run("query", func(t *testing.T) {
		repository, mock := mockRepository(t)
		mock.ExpectQuery("SELECT id, revision").WillReturnError(problem)
		if _, err := repository.ListRecords(ctx, ownerID); !errors.Is(err, problem) {
			t.Fatalf("list query failure: %v", err)
		}
	})
	t.Run("scan", func(t *testing.T) {
		repository, mock := mockRepository(t)
		mock.ExpectQuery("SELECT id, revision").WillReturnRows(sqlmock.NewRows([]string{"id", "revision", "ciphertext", "updated_at"}).
			AddRow(recordID, "invalid revision", []byte{1}, testTime)).RowsWillBeClosed()
		if _, err := repository.ListRecords(ctx, ownerID); err == nil {
			t.Fatal("scan failure ignored")
		}
	})
	t.Run("rows", func(t *testing.T) {
		repository, mock := mockRepository(t)
		mock.ExpectQuery("SELECT id, revision").WillReturnRows(recordRows(1).RowError(0, problem)).RowsWillBeClosed()
		if _, err := repository.ListRecords(ctx, ownerID); !errors.Is(err, problem) {
			t.Fatalf("row failure ignored: %v", err)
		}
	})
	t.Run("empty", func(t *testing.T) {
		repository, mock := mockRepository(t)
		mock.ExpectQuery("SELECT id, revision").WillReturnRows(sqlmock.NewRows([]string{"id", "revision", "ciphertext", "updated_at"}))
		if records, err := repository.ListRecords(ctx, ownerID); err != nil || records == nil || len(records) != 0 {
			t.Fatalf("empty snapshot: %v %v", records, err)
		}
	})
	t.Run("not found", func(t *testing.T) {
		repository, mock := mockRepository(t)
		mock.ExpectQuery("SELECT id, revision").WithArgs(ownerID, recordID).
			WillReturnRows(sqlmock.NewRows([]string{"id", "revision", "ciphertext", "updated_at"}))
		if _, err := repository.GetRecord(ctx, ownerID, recordID); !errors.Is(err, model.ErrNotFound) {
			t.Fatalf("missing entry: %v", err)
		}
	})
}

func TestWriteAndRevisionLookupFailures(t *testing.T) {
	ctx := context.Background()
	problem := errors.New("write failure")
	repository, mock := mockRepository(t)
	expectCapacityLock(mock, 1, 32, 32, 1)
	mock.ExpectQuery("UPDATE records").WillReturnError(problem)
	mock.ExpectRollback()
	if _, err := repository.PutRecord(ctx, ownerID, recordID, 1, nil); !errors.Is(err, problem) {
		t.Fatalf("update failure: %v", err)
	}
	mock.ExpectExec("DELETE FROM records").WillReturnError(problem)
	if err := repository.DeleteRecord(ctx, ownerID, recordID, 1); !errors.Is(err, problem) {
		t.Fatalf("delete failure: %v", err)
	}
	mock.ExpectExec("DELETE FROM records").WillReturnResult(sqlmock.NewErrorResult(problem))
	if err := repository.DeleteRecord(ctx, ownerID, recordID, 1); !errors.Is(err, problem) {
		t.Fatalf("delete result failure: %v", err)
	}
	mock.ExpectExec("DELETE FROM records").WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery("SELECT EXISTS").WillReturnError(problem)
	if err := repository.DeleteRecord(ctx, ownerID, recordID, 1); !errors.Is(err, problem) {
		t.Fatalf("revision lookup failure: %v", err)
	}
}

func TestVaultCapacityAccountsForReplacementAndLimits(t *testing.T) {
	ctx := context.Background()
	for _, test := range []struct {
		name                           string
		previous, oldSize, used, count int64
		full                           bool
	}{
		{name: "create at byte boundary", used: model.MaxVaultCiphertextSize - 32, count: 5},
		{name: "create exceeds byte boundary", used: model.MaxVaultCiphertextSize - 31, count: 5, full: true},
		{name: "create exceeds count", count: model.MaxVaultRecords, full: true},
		{name: "create at count boundary", count: model.MaxVaultRecords - 1},
		{name: "replace at full capacity", previous: 1, oldSize: 32, used: model.MaxVaultCiphertextSize, count: model.MaxVaultRecords},
		{name: "shrink at full capacity", previous: 1, oldSize: 64, used: model.MaxVaultCiphertextSize, count: model.MaxVaultRecords},
		{name: "grow exceeds capacity", previous: 1, oldSize: 31, used: model.MaxVaultCiphertextSize, count: 5, full: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			repository, mock := mockRepository(t)
			expectCapacityLock(mock, test.previous, test.oldSize, test.used, test.count)
			data := make([]byte, 32)
			if test.full {
				mock.ExpectRollback()
			} else {
				if test.previous == 0 {
					mock.ExpectQuery("INSERT INTO records").WithArgs(ownerID, recordID, data).WillReturnRows(recordRows(1))
				} else {
					mock.ExpectQuery("UPDATE records").WithArgs(ownerID, recordID, test.previous, data).WillReturnRows(recordRows(test.previous + 1))
				}
				mock.ExpectCommit()
			}
			record, err := repository.PutRecord(ctx, ownerID, recordID, test.previous, data)
			if test.full {
				if !errors.Is(err, model.ErrCapacity) {
					t.Fatalf("capacity should reject write before data changes: %v", err)
				}
			} else if err != nil || record.Revision != test.previous+1 {
				t.Fatalf("write at capacity boundary: %+v %v", record, err)
			}
		})
	}
}

func TestCapacityTransactionFailuresRollbackAndPreserveErrors(t *testing.T) {
	ctx := context.Background()
	problem := errors.New("transaction failure")
	for _, stage := range []string{"begin", "owner", "existing create", "existing update", "duplicate create", "aggregate", "commit", "concurrent delete"} {
		t.Run(stage, func(t *testing.T) {
			repository, mock := mockRepository(t)
			wanted := problem
			expected := int64(0)
			if stage == "existing update" || stage == "concurrent delete" {
				expected = 1
			}
			if stage == "begin" {
				mock.ExpectBegin().WillReturnError(problem)
			} else if stage == "commit" || stage == "concurrent delete" {
				expectCapacityLock(mock, expected, 32, 32, 1)
				if stage == "commit" {
					mock.ExpectQuery("INSERT INTO records").WillReturnRows(recordRows(1))
					mock.ExpectCommit().WillReturnError(problem)
				} else {
					mock.ExpectQuery("UPDATE records").WillReturnRows(sqlmock.NewRows([]string{"id", "revision", "ciphertext", "updated_at"}))
					mock.ExpectRollback()
					wanted = model.ErrNotFound
				}
			} else {
				mock.ExpectBegin()
				owner := mock.ExpectQuery("SELECT id FROM users").WithArgs(ownerID)
				if stage == "owner" {
					owner.WillReturnError(problem)
				} else {
					owner.WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(ownerID))
					existing := mock.ExpectQuery("SELECT revision, octet_length").WithArgs(ownerID, recordID)
					switch stage {
					case "existing create", "existing update":
						existing.WillReturnError(problem)
					case "duplicate create":
						existing.WillReturnRows(sqlmock.NewRows([]string{"revision", "size"}).AddRow(1, 32))
						wanted = model.ErrConflict
					case "aggregate":
						existing.WillReturnRows(sqlmock.NewRows([]string{"revision", "size"}))
						mock.ExpectQuery("SELECT COALESCE").WithArgs(ownerID).WillReturnError(problem)
					}
				}
				mock.ExpectRollback()
			}
			if _, err := repository.PutRecord(ctx, ownerID, recordID, expected, make([]byte, 32)); !errors.Is(err, wanted) {
				t.Fatalf("%s failure: %v want %v", stage, err, wanted)
			}
		})
	}
}

func TestStartupRejectsMissingMalformedAndCancelledDatabase(t *testing.T) {
	if _, err := New(context.Background(), ""); err == nil {
		t.Fatal("missing DSN accepted")
	}
	if _, err := New(context.Background(), "host='unterminated"); err == nil {
		t.Fatal("malformed DSN accepted")
	}
	if _, err := New(context.Background(), "postgres://user:secret-marker%zz@localhost/db"); err == nil || strings.Contains(err.Error(), "secret-marker") {
		t.Fatalf("startup error leaked connection credentials: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := New(ctx, "host=localhost dbname=unused"); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled startup error lost: %v", err)
	}
	repository, _ := mockRepository(t)
	if err := migrateDatabase(ctx, repository.db); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled migration: %v", err)
	}
}

func TestMigrationsAreEmbeddedAndLeaveConnectionPoolUsable(t *testing.T) {
	repository, mock := mockRepository(t)
	mock.ExpectExec(regexp.QuoteMeta("SELECT set_config('statement_timeout', $1, false)")).
		WithArgs("30000").WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectPing()
	mock.ExpectQuery(regexp.QuoteMeta("SELECT CURRENT_DATABASE()")).WillReturnRows(sqlmock.NewRows([]string{"database"}).AddRow("gophkeeper"))
	mock.ExpectQuery(regexp.QuoteMeta("SELECT CURRENT_SCHEMA()")).WillReturnRows(sqlmock.NewRows([]string{"schema"}).AddRow("public"))
	mock.ExpectExec("SELECT pg_advisory_lock").WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectQuery("SELECT COUNT\\(1\\) FROM information_schema.tables").WithArgs("public", "schema_migrations").
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(1))
	mock.ExpectExec("SELECT pg_advisory_unlock").WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec("SELECT pg_advisory_lock").WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectQuery("SELECT version, dirty FROM").WillReturnRows(sqlmock.NewRows([]string{"version", "dirty"}).AddRow(1, false))
	mock.ExpectExec("SELECT pg_advisory_unlock").WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec("RESET statement_timeout").WillReturnResult(sqlmock.NewResult(0, 0))
	if err := migrateDatabase(context.Background(), repository.db); err != nil {
		t.Fatal(err)
	}
	if repository.db.Stats().InUse != 0 {
		t.Fatal("migration leaked its borrowed connection")
	}
	mock.ExpectPing()
	if err := repository.Ping(context.Background()); err != nil {
		t.Fatalf("migration closed shared pool: %v", err)
	}
}

func TestMigrationAdvisoryLockTimeoutPreservesFailureAndRestoresSession(t *testing.T) {
	repository, mock := mockRepository(t)
	problem := &pq.Error{Code: "57014", Message: "canceling statement due to statement timeout"}
	mock.ExpectExec(regexp.QuoteMeta("SELECT set_config('statement_timeout', $1, false)")).
		WithArgs(sqlmock.AnyArg()).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectPing()
	mock.ExpectQuery(regexp.QuoteMeta("SELECT CURRENT_DATABASE()")).
		WillReturnRows(sqlmock.NewRows([]string{"database"}).AddRow("gophkeeper"))
	mock.ExpectQuery(regexp.QuoteMeta("SELECT CURRENT_SCHEMA()")).
		WillReturnRows(sqlmock.NewRows([]string{"schema"}).AddRow("public"))
	mock.ExpectExec("SELECT pg_advisory_lock").WillReturnError(problem)
	mock.ExpectExec("RESET statement_timeout").WillReturnResult(sqlmock.NewResult(0, 0))
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := migrateDatabase(ctx, repository.db); err == nil || !strings.Contains(err.Error(), "statement timeout") {
		t.Fatalf("advisory lock timeout ignored: %v", err)
	}
	if repository.db.Stats().InUse != 0 {
		t.Fatal("migration error leaked a borrowed connection")
	}
}

func TestDatabaseErrorPreservesUnexpectedFailures(t *testing.T) {
	problem := &pq.Error{Code: "08006"}
	if err := databaseError("query", problem); !errors.Is(err, problem) {
		t.Fatalf("unexpected error lost: %v", err)
	}
	if err := databaseError("query", sql.ErrNoRows); !errors.Is(err, model.ErrNotFound) {
		t.Fatalf("missing row not mapped: %v", err)
	}
}
