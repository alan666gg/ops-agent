package notify

import (
	"database/sql"
	"path/filepath"
	"testing"
	"time"

	_ "modernc.org/sqlite"
)

func TestSQLiteStoreMigratesOldSchemaAndPersistsNewFields(t *testing.T) {
	path := filepath.Join(t.TempDir(), "notify-state.db")

	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec(`
CREATE TABLE notify_state (
  key TEXT PRIMARY KEY,
  last_status TEXT NOT NULL,
  last_fingerprint TEXT NOT NULL,
  last_notified_at TEXT NOT NULL,
  last_changed_at TEXT NOT NULL
);
INSERT INTO notify_state(key, last_status, last_fingerprint, last_notified_at, last_changed_at)
VALUES('ops-scheduler|prod', 'fail', 'fp1', '2026-03-18T10:00:00Z', '2026-03-18T10:00:00Z');
`)
	if err != nil {
		_ = db.Close()
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	store := SQLiteStore{Path: path}
	st, ok, err := store.Get("ops-scheduler|prod")
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("expected migrated row to exist")
	}
	if st.Open || st.FailureStreak != 0 || st.RecoveryStreak != 0 {
		t.Fatalf("expected migrated defaults, got %+v", st)
	}

	expected := State{
		Key:             "ops-scheduler|prod",
		LastStatus:      "warn",
		LastFingerprint: "fp2",
		LastNotifiedAt:  time.Date(2026, 3, 18, 11, 0, 0, 0, time.UTC),
		LastChangedAt:   time.Date(2026, 3, 18, 11, 5, 0, 0, time.UTC),
		Open:            true,
		OpenStatus:      "warn",
		OpenFingerprint: "fp2",
		FailureStreak:   3,
		RecoveryStreak:  1,
	}
	if err := store.Put(expected); err != nil {
		t.Fatal(err)
	}

	got, ok, err := store.Get(expected.Key)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("expected row after put")
	}
	if got.Key != expected.Key ||
		got.LastStatus != expected.LastStatus ||
		got.LastFingerprint != expected.LastFingerprint ||
		!got.LastNotifiedAt.Equal(expected.LastNotifiedAt) ||
		!got.LastChangedAt.Equal(expected.LastChangedAt) ||
		got.Open != expected.Open ||
		got.OpenStatus != expected.OpenStatus ||
		got.OpenFingerprint != expected.OpenFingerprint ||
		got.FailureStreak != expected.FailureStreak ||
		got.RecoveryStreak != expected.RecoveryStreak {
		t.Fatalf("unexpected stored state: %+v", got)
	}
}
