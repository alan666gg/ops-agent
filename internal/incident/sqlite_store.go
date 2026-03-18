package incident

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

type SQLiteStore struct {
	Path string
}

func NewSQLiteStore(path string) Store {
	if strings.TrimSpace(path) == "" {
		return nil
	}
	return SQLiteStore{Path: path}
}

func (s SQLiteStore) SyncReport(report Report, now time.Time) (Record, error) {
	db, err := s.open()
	if err != nil {
		return Record{}, err
	}
	defer db.Close()

	id := recordID(report)
	prev, ok, err := s.get(db, id)
	if err != nil {
		return Record{}, err
	}
	next := syncRecord(prev, ok, report, now)
	if err := s.put(db, next); err != nil {
		return Record{}, err
	}
	return next, nil
}

func (s SQLiteStore) Get(id string) (Record, bool, error) {
	db, err := s.open()
	if err != nil {
		return Record{}, false, err
	}
	defer db.Close()
	return s.get(db, id)
}

func (s SQLiteStore) List(filter Filter) ([]Record, error) {
	db, err := s.open()
	if err != nil {
		return nil, err
	}
	defer db.Close()

	query := `
SELECT id, source, scope_key, project, env, status, summary, fingerprint, highlights_json, external_json, silence_json, open, acknowledged, acknowledged_by, acknowledged_at, owner, note, first_seen_at, last_seen_at, last_changed_at, closed_at, updated_at, fail_count, warn_count, suppressed_count
FROM incident_records
WHERE 1=1
`
	args := make([]any, 0, 8)
	if filter.OpenOnly {
		query += " AND open = 1"
	}
	if strings.TrimSpace(filter.Env) != "" {
		query += " AND env = ?"
		args = append(args, strings.TrimSpace(filter.Env))
	}
	if strings.TrimSpace(filter.Source) != "" {
		query += " AND source = ?"
		args = append(args, strings.TrimSpace(filter.Source))
	}
	if len(filter.Projects) > 0 {
		query += " AND project IN (" + placeholders(len(filter.Projects)) + ")"
		for _, project := range filter.Projects {
			args = append(args, defaultProject(project))
		}
	}
	query += " ORDER BY open DESC, CASE status WHEN 'fail' THEN 2 WHEN 'warn' THEN 1 ELSE 0 END DESC, last_changed_at DESC"
	if filter.Limit > 0 {
		query += " LIMIT ?"
		args = append(args, filter.Limit)
	}
	rows, err := db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []Record
	for rows.Next() {
		rec, err := scanRecord(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, rec)
	}
	return out, rows.Err()
}

func (s SQLiteStore) Ack(id, actor, note string, now time.Time) (Record, error) {
	return s.update(id, func(rec *Record) error {
		rec.Acknowledged = true
		rec.AcknowledgedBy = strings.TrimSpace(actor)
		rec.AcknowledgedAt = now.UTC()
		if strings.TrimSpace(note) != "" {
			rec.Note = strings.TrimSpace(note)
		}
		rec.UpdatedAt = now.UTC()
		return nil
	})
}

func (s SQLiteStore) Assign(id, owner, actor, note string, now time.Time) (Record, error) {
	return s.update(id, func(rec *Record) error {
		rec.Owner = strings.TrimSpace(owner)
		if strings.TrimSpace(note) != "" {
			if strings.TrimSpace(actor) != "" {
				rec.Note = strings.TrimSpace(note) + " (by " + strings.TrimSpace(actor) + ")"
			} else {
				rec.Note = strings.TrimSpace(note)
			}
		}
		rec.UpdatedAt = now.UTC()
		return nil
	})
}

func (s SQLiteStore) SetSilence(id string, silence ExternalSilence, now time.Time) (Record, error) {
	return s.update(id, func(rec *Record) error {
		silence.Status = strings.TrimSpace(silence.Status)
		if silence.Status == "" {
			silence.Status = "active"
		}
		silence.UpdatedAt = now.UTC()
		rec.Silence = cloneExternalSilence(&silence)
		rec.UpdatedAt = now.UTC()
		return nil
	})
}

func (s SQLiteStore) ExpireSilence(id, actor, note string, now time.Time) (Record, error) {
	return s.update(id, func(rec *Record) error {
		if rec.Silence == nil {
			return fmt.Errorf("incident has no silence: %s", id)
		}
		silence := cloneExternalSilence(rec.Silence)
		silence.Status = "expired"
		silence.ExpiredAt = now.UTC()
		silence.ExpiredBy = strings.TrimSpace(actor)
		silence.UpdatedAt = now.UTC()
		rec.Silence = silence
		if note = strings.TrimSpace(note); note != "" {
			rec.Note = note
		}
		rec.UpdatedAt = now.UTC()
		return nil
	})
}

func (s SQLiteStore) update(id string, fn func(*Record) error) (Record, error) {
	db, err := s.open()
	if err != nil {
		return Record{}, err
	}
	defer db.Close()
	rec, ok, err := s.get(db, id)
	if err != nil {
		return Record{}, err
	}
	if !ok {
		return Record{}, fmt.Errorf("incident not found: %s", id)
	}
	if err := fn(&rec); err != nil {
		return Record{}, err
	}
	if err := s.put(db, rec); err != nil {
		return Record{}, err
	}
	return rec, nil
}

func (s SQLiteStore) open() (*sql.DB, error) {
	if err := os.MkdirAll(filepath.Dir(s.Path), 0o755); err != nil {
		return nil, err
	}
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
CREATE TABLE IF NOT EXISTS incident_records (
  id TEXT PRIMARY KEY,
  source TEXT NOT NULL DEFAULT '',
  scope_key TEXT NOT NULL DEFAULT '',
  project TEXT NOT NULL DEFAULT 'default',
  env TEXT NOT NULL DEFAULT '',
  status TEXT NOT NULL DEFAULT '',
  summary TEXT NOT NULL DEFAULT '',
  fingerprint TEXT NOT NULL DEFAULT '',
  highlights_json TEXT NOT NULL DEFAULT '[]',
  external_json TEXT NOT NULL DEFAULT 'null',
  silence_json TEXT NOT NULL DEFAULT 'null',
  open INTEGER NOT NULL DEFAULT 0,
  acknowledged INTEGER NOT NULL DEFAULT 0,
  acknowledged_by TEXT NOT NULL DEFAULT '',
  acknowledged_at TEXT NOT NULL DEFAULT '',
  owner TEXT NOT NULL DEFAULT '',
  note TEXT NOT NULL DEFAULT '',
  first_seen_at TEXT NOT NULL DEFAULT '',
  last_seen_at TEXT NOT NULL DEFAULT '',
  last_changed_at TEXT NOT NULL DEFAULT '',
  closed_at TEXT NOT NULL DEFAULT '',
  updated_at TEXT NOT NULL DEFAULT '',
  fail_count INTEGER NOT NULL DEFAULT 0,
  warn_count INTEGER NOT NULL DEFAULT 0,
  suppressed_count INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_incident_open_project ON incident_records(open, project, last_changed_at DESC);
CREATE INDEX IF NOT EXISTS idx_incident_project_env ON incident_records(project, env, open, last_changed_at DESC);
`)
	if err != nil {
		return err
	}
	_, err = db.Exec(`ALTER TABLE incident_records ADD COLUMN scope_key TEXT NOT NULL DEFAULT ''`)
	if err != nil && !strings.Contains(strings.ToLower(err.Error()), "duplicate column name") {
		return err
	}
	_, err = db.Exec(`ALTER TABLE incident_records ADD COLUMN external_json TEXT NOT NULL DEFAULT 'null'`)
	if err != nil && !strings.Contains(strings.ToLower(err.Error()), "duplicate column name") {
		return err
	}
	_, err = db.Exec(`ALTER TABLE incident_records ADD COLUMN silence_json TEXT NOT NULL DEFAULT 'null'`)
	if err != nil && !strings.Contains(strings.ToLower(err.Error()), "duplicate column name") {
		return err
	}
	return nil
}

func (s SQLiteStore) get(db *sql.DB, id string) (Record, bool, error) {
	row := db.QueryRow(`
SELECT id, source, scope_key, project, env, status, summary, fingerprint, highlights_json, external_json, silence_json, open, acknowledged, acknowledged_by, acknowledged_at, owner, note, first_seen_at, last_seen_at, last_changed_at, closed_at, updated_at, fail_count, warn_count, suppressed_count
FROM incident_records
WHERE id = ?
`, strings.TrimSpace(id))
	rec, err := scanRecord(row)
	if err != nil {
		if err == sql.ErrNoRows {
			return Record{}, false, nil
		}
		return Record{}, false, err
	}
	return rec, true, nil
}

func (s SQLiteStore) put(db *sql.DB, rec Record) error {
	highlightsJSON, err := json.Marshal(rec.Highlights)
	if err != nil {
		return err
	}
	externalJSON, err := json.Marshal(rec.External)
	if err != nil {
		return err
	}
	silenceJSON, err := json.Marshal(rec.Silence)
	if err != nil {
		return err
	}
	_, err = db.Exec(`
INSERT INTO incident_records(id, source, scope_key, project, env, status, summary, fingerprint, highlights_json, external_json, silence_json, open, acknowledged, acknowledged_by, acknowledged_at, owner, note, first_seen_at, last_seen_at, last_changed_at, closed_at, updated_at, fail_count, warn_count, suppressed_count)
VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(id) DO UPDATE SET
  source=excluded.source,
  scope_key=excluded.scope_key,
  project=excluded.project,
  env=excluded.env,
  status=excluded.status,
  summary=excluded.summary,
  fingerprint=excluded.fingerprint,
  highlights_json=excluded.highlights_json,
  external_json=excluded.external_json,
  silence_json=excluded.silence_json,
  open=excluded.open,
  acknowledged=excluded.acknowledged,
  acknowledged_by=excluded.acknowledged_by,
  acknowledged_at=excluded.acknowledged_at,
  owner=excluded.owner,
  note=excluded.note,
  first_seen_at=excluded.first_seen_at,
  last_seen_at=excluded.last_seen_at,
  last_changed_at=excluded.last_changed_at,
  closed_at=excluded.closed_at,
  updated_at=excluded.updated_at,
  fail_count=excluded.fail_count,
  warn_count=excluded.warn_count,
  suppressed_count=excluded.suppressed_count
`, strings.TrimSpace(rec.ID), rec.Source, rec.Key, defaultProject(rec.Project), rec.Env, rec.Status, rec.Summary, rec.Fingerprint, string(highlightsJSON), string(externalJSON), string(silenceJSON), boolToInt(rec.Open), boolToInt(rec.Acknowledged), rec.AcknowledgedBy, formatTime(rec.AcknowledgedAt), rec.Owner, rec.Note, formatTime(rec.FirstSeenAt), formatTime(rec.LastSeenAt), formatTime(rec.LastChangedAt), formatTime(rec.ClosedAt), formatTime(rec.UpdatedAt), rec.FailCount, rec.WarnCount, rec.SuppressedCount)
	return err
}

type recordScanner interface {
	Scan(dest ...any) error
}

func scanRecord(s recordScanner) (Record, error) {
	var rec Record
	var highlightsJSON string
	var externalJSON string
	var silenceJSON string
	var openInt, ackInt int
	var ackAt, firstSeen, lastSeen, lastChanged, closedAt, updatedAt string
	if err := s.Scan(&rec.ID, &rec.Source, &rec.Key, &rec.Project, &rec.Env, &rec.Status, &rec.Summary, &rec.Fingerprint, &highlightsJSON, &externalJSON, &silenceJSON, &openInt, &ackInt, &rec.AcknowledgedBy, &ackAt, &rec.Owner, &rec.Note, &firstSeen, &lastSeen, &lastChanged, &closedAt, &updatedAt, &rec.FailCount, &rec.WarnCount, &rec.SuppressedCount); err != nil {
		return Record{}, err
	}
	rec.Open = openInt == 1
	rec.Acknowledged = ackInt == 1
	_ = json.Unmarshal([]byte(highlightsJSON), &rec.Highlights)
	_ = json.Unmarshal([]byte(externalJSON), &rec.External)
	_ = json.Unmarshal([]byte(silenceJSON), &rec.Silence)
	rec.AcknowledgedAt, _ = parseTime(ackAt)
	rec.FirstSeenAt, _ = parseTime(firstSeen)
	rec.LastSeenAt, _ = parseTime(lastSeen)
	rec.LastChangedAt, _ = parseTime(lastChanged)
	rec.ClosedAt, _ = parseTime(closedAt)
	rec.UpdatedAt, _ = parseTime(updatedAt)
	return rec, nil
}

func parseTime(v string) (time.Time, error) {
	v = strings.TrimSpace(v)
	if v == "" {
		return time.Time{}, nil
	}
	return time.Parse(time.RFC3339Nano, v)
}

func formatTime(v time.Time) string {
	if v.IsZero() {
		return ""
	}
	return v.UTC().Format(time.RFC3339Nano)
}

func placeholders(n int) string {
	if n <= 0 {
		return ""
	}
	items := make([]string, n)
	for i := range items {
		items[i] = "?"
	}
	return strings.Join(items, ",")
}

func boolToInt(v bool) int {
	if v {
		return 1
	}
	return 0
}
