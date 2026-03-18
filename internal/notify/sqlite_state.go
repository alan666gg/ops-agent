package notify

import (
	"database/sql"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

type SQLiteStore struct {
	Path string
}

func (s SQLiteStore) open() (*sql.DB, error) {
	db, err := sql.Open("sqlite", s.Path)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	if err := s.ensureSchema(db); err != nil {
		_ = db.Close()
		return nil, err
	}
	return db, nil
}

func (s SQLiteStore) ensureSchema(db *sql.DB) error {
	_, err := db.Exec(`
CREATE TABLE IF NOT EXISTS notify_state (
  key TEXT PRIMARY KEY,
  last_status TEXT NOT NULL DEFAULT '',
  last_fingerprint TEXT NOT NULL DEFAULT '',
  last_notified_at TEXT NOT NULL DEFAULT '',
  last_changed_at TEXT NOT NULL DEFAULT '',
  open INTEGER NOT NULL DEFAULT 0,
  open_status TEXT NOT NULL DEFAULT '',
  open_fingerprint TEXT NOT NULL DEFAULT '',
  failure_streak INTEGER NOT NULL DEFAULT 0,
  recovery_streak INTEGER NOT NULL DEFAULT 0
);
`)
	if err != nil {
		return err
	}
	for _, col := range []struct {
		name string
		def  string
	}{
		{name: "open", def: "INTEGER NOT NULL DEFAULT 0"},
		{name: "open_status", def: "TEXT NOT NULL DEFAULT ''"},
		{name: "open_fingerprint", def: "TEXT NOT NULL DEFAULT ''"},
		{name: "failure_streak", def: "INTEGER NOT NULL DEFAULT 0"},
		{name: "recovery_streak", def: "INTEGER NOT NULL DEFAULT 0"},
	} {
		if err := ensureColumn(db, "notify_state", col.name, col.def); err != nil {
			return err
		}
	}
	return nil
}

func ensureColumn(db *sql.DB, table, name, def string) error {
	rows, err := db.Query("PRAGMA table_info(" + table + ")")
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var (
			cid       int
			colName   string
			colType   string
			notNull   int
			defaultV  sql.NullString
			primaryPK int
		)
		if err := rows.Scan(&cid, &colName, &colType, &notNull, &defaultV, &primaryPK); err != nil {
			return err
		}
		if strings.EqualFold(colName, name) {
			return nil
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}
	_, err = db.Exec("ALTER TABLE " + table + " ADD COLUMN " + name + " " + def)
	return err
}

func (s SQLiteStore) Get(key string) (State, bool, error) {
	db, err := s.open()
	if err != nil {
		return State{}, false, err
	}
	defer db.Close()
	row := db.QueryRow(`SELECT key, last_status, last_fingerprint, last_notified_at, last_changed_at, open, open_status, open_fingerprint, failure_streak, recovery_streak FROM notify_state WHERE key=?`, key)
	var st State
	var lastNotified, lastChanged string
	var open int
	if err := row.Scan(&st.Key, &st.LastStatus, &st.LastFingerprint, &lastNotified, &lastChanged, &open, &st.OpenStatus, &st.OpenFingerprint, &st.FailureStreak, &st.RecoveryStreak); err != nil {
		if err == sql.ErrNoRows {
			return State{}, false, nil
		}
		return State{}, false, err
	}
	st.LastNotifiedAt, _ = time.Parse(time.RFC3339Nano, lastNotified)
	st.LastChangedAt, _ = time.Parse(time.RFC3339Nano, lastChanged)
	st.Open = open != 0
	return st, true, nil
}

func (s SQLiteStore) Put(state State) error {
	db, err := s.open()
	if err != nil {
		return err
	}
	defer db.Close()
	_, err = db.Exec(`
INSERT INTO notify_state(key, last_status, last_fingerprint, last_notified_at, last_changed_at, open, open_status, open_fingerprint, failure_streak, recovery_streak)
VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(key) DO UPDATE SET
  last_status=excluded.last_status,
  last_fingerprint=excluded.last_fingerprint,
  last_notified_at=excluded.last_notified_at,
  last_changed_at=excluded.last_changed_at,
  open=excluded.open,
  open_status=excluded.open_status,
  open_fingerprint=excluded.open_fingerprint,
  failure_streak=excluded.failure_streak,
  recovery_streak=excluded.recovery_streak
`, strings.TrimSpace(state.Key), state.LastStatus, state.LastFingerprint, state.LastNotifiedAt.UTC().Format(time.RFC3339Nano), state.LastChangedAt.UTC().Format(time.RFC3339Nano), boolToInt(state.Open), state.OpenStatus, state.OpenFingerprint, state.FailureStreak, state.RecoveryStreak)
	return err
}

func boolToInt(v bool) int {
	if v {
		return 1
	}
	return 0
}
