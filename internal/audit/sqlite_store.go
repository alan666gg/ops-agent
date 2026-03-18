package audit

import (
	"database/sql"
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

func (s SQLiteStore) Driver() string {
	return "sqlite"
}

func (s SQLiteStore) Location() string {
	return s.Path
}

func (s SQLiteStore) Append(evt Event) error {
	db, err := s.open()
	if err != nil {
		return err
	}
	defer db.Close()
	_, err = db.Exec(`
INSERT INTO audit_events(time, actor, action, project, env, target_host, target, status, message, requires_approval)
VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
`, evt.Time.UTC().Format(time.RFC3339Nano), evt.Actor, evt.Action, defaultProject(evt.Project), evt.Env, evt.TargetHost, evt.Target, evt.Status, evt.Message, boolToInt(evt.RequiresOK))
	return err
}

func (s SQLiteStore) CountRecentAutoActions(project, env string, since time.Time) (int, error) {
	db, err := s.open()
	if err != nil {
		return 0, err
	}
	defer db.Close()

	query := `
SELECT action, status, requires_approval
FROM audit_events
WHERE time >= ?
`
	args := []any{since.UTC().Format(time.RFC3339Nano)}
	if strings.TrimSpace(project) != "" {
		query += " AND project = ?"
		args = append(args, defaultProject(project))
	}
	if strings.TrimSpace(env) != "" {
		query += " AND env = ?"
		args = append(args, strings.TrimSpace(env))
	}
	rows, err := db.Query(query, args...)
	if err != nil {
		return 0, err
	}
	defer rows.Close()

	count := 0
	for rows.Next() {
		var actionName, status string
		var requiresApproval int
		if err := rows.Scan(&actionName, &status, &requiresApproval); err != nil {
			return 0, err
		}
		evt := Event{Action: actionName, Status: status, RequiresOK: requiresApproval == 1}
		if evt.RequiresOK || !countableAction(evt) {
			continue
		}
		count++
	}
	return count, rows.Err()
}

func (s SQLiteStore) List(q Query) ([]Event, error) {
	db, err := s.open()
	if err != nil {
		return nil, err
	}
	defer db.Close()

	query := `
SELECT time, actor, action, project, env, target_host, target, status, message, requires_approval
FROM audit_events
WHERE 1=1
`
	args := make([]any, 0, 8)
	if !q.Since.IsZero() {
		query += " AND time >= ?"
		args = append(args, q.Since.UTC().Format(time.RFC3339Nano))
	}
	if len(q.Projects) > 0 {
		query += " AND project IN (" + placeholders(len(q.Projects)) + ")"
		for _, project := range q.Projects {
			args = append(args, defaultProject(project))
		}
	}
	if strings.TrimSpace(q.Env) != "" {
		query += " AND env = ?"
		args = append(args, strings.TrimSpace(q.Env))
	}
	if len(q.Actions) > 0 {
		query += " AND action IN (" + placeholders(len(q.Actions)) + ")"
		for _, actionName := range q.Actions {
			args = append(args, strings.TrimSpace(actionName))
		}
	}
	query += " ORDER BY time DESC"
	if q.Limit > 0 {
		query += " LIMIT ?"
		args = append(args, q.Limit)
	}

	rows, err := db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []Event
	for rows.Next() {
		var evt Event
		var at string
		var requiresApproval int
		if err := rows.Scan(&at, &evt.Actor, &evt.Action, &evt.Project, &evt.Env, &evt.TargetHost, &evt.Target, &evt.Status, &evt.Message, &requiresApproval); err != nil {
			return nil, err
		}
		evt.Time, _ = time.Parse(time.RFC3339Nano, at)
		evt.RequiresOK = requiresApproval == 1
		out = append(out, evt)
	}
	return out, rows.Err()
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
CREATE TABLE IF NOT EXISTS audit_events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  time TEXT NOT NULL,
  actor TEXT NOT NULL DEFAULT '',
  action TEXT NOT NULL DEFAULT '',
  project TEXT NOT NULL DEFAULT 'default',
  env TEXT NOT NULL DEFAULT '',
  target_host TEXT NOT NULL DEFAULT '',
  target TEXT NOT NULL DEFAULT '',
  status TEXT NOT NULL DEFAULT '',
  message TEXT NOT NULL DEFAULT '',
  requires_approval INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_audit_time ON audit_events(time DESC);
CREATE INDEX IF NOT EXISTS idx_audit_project_env_time ON audit_events(project, env, time DESC);
CREATE INDEX IF NOT EXISTS idx_audit_action_time ON audit_events(action, time DESC);
`)
	if err != nil {
		return err
	}
	_, err = db.Exec(`ALTER TABLE audit_events ADD COLUMN project TEXT NOT NULL DEFAULT 'default'`)
	if err != nil && !strings.Contains(strings.ToLower(err.Error()), "duplicate column name") {
		return err
	}
	return nil
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

func OpenSQLite(path string) (Store, error) {
	return SQLiteStore{Path: path}, nil
}

func RecentSQLite(path string, q Query) ([]Event, error) {
	return SQLiteStore{Path: path}.List(q)
}

func CountRecentAutoActionsSQLite(path, project, env string, since time.Time) (int, error) {
	return SQLiteStore{Path: path}.CountRecentAutoActions(project, env, since)
}

func mustProject(project string) string {
	return defaultProject(project)
}

func scanSQLiteEvent(row scanner) (Event, error) {
	var evt Event
	var at string
	var requiresApproval int
	if err := row.Scan(&at, &evt.Actor, &evt.Action, &evt.Project, &evt.Env, &evt.TargetHost, &evt.Target, &evt.Status, &evt.Message, &requiresApproval); err != nil {
		return Event{}, err
	}
	evt.Time, _ = time.Parse(time.RFC3339Nano, at)
	evt.RequiresOK = requiresApproval == 1
	return evt, nil
}

type scanner interface {
	Scan(dest ...any) error
}

func EventFromRow(row *sql.Row) (Event, error) {
	evt, err := scanSQLiteEvent(row)
	if err != nil {
		return Event{}, fmt.Errorf("scan audit event: %w", err)
	}
	return evt, nil
}
