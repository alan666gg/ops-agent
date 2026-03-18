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
  last_status TEXT NOT NULL,
  last_fingerprint TEXT NOT NULL,
  last_notified_at TEXT NOT NULL,
  last_changed_at TEXT NOT NULL
);
`)
	return err
}

func (s SQLiteStore) Get(key string) (State, bool, error) {
	db, err := s.open()
	if err != nil {
		return State{}, false, err
	}
	defer db.Close()
	row := db.QueryRow(`SELECT key, last_status, last_fingerprint, last_notified_at, last_changed_at FROM notify_state WHERE key=?`, key)
	var st State
	var lastNotified, lastChanged string
	if err := row.Scan(&st.Key, &st.LastStatus, &st.LastFingerprint, &lastNotified, &lastChanged); err != nil {
		if err == sql.ErrNoRows {
			return State{}, false, nil
		}
		return State{}, false, err
	}
	st.LastNotifiedAt, _ = time.Parse(time.RFC3339Nano, lastNotified)
	st.LastChangedAt, _ = time.Parse(time.RFC3339Nano, lastChanged)
	return st, true, nil
}

func (s SQLiteStore) Put(state State) error {
	db, err := s.open()
	if err != nil {
		return err
	}
	defer db.Close()
	_, err = db.Exec(`
INSERT INTO notify_state(key, last_status, last_fingerprint, last_notified_at, last_changed_at)
VALUES(?, ?, ?, ?, ?)
ON CONFLICT(key) DO UPDATE SET
  last_status=excluded.last_status,
  last_fingerprint=excluded.last_fingerprint,
  last_notified_at=excluded.last_notified_at,
  last_changed_at=excluded.last_changed_at
`, strings.TrimSpace(state.Key), state.LastStatus, state.LastFingerprint, state.LastNotifiedAt.UTC().Format(time.RFC3339Nano), state.LastChangedAt.UTC().Format(time.RFC3339Nano))
	return err
}
