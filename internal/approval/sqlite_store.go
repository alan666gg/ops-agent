package approval

import (
	"database/sql"
	"fmt"
	"sort"
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
CREATE TABLE IF NOT EXISTS approval_requests (
  id TEXT PRIMARY KEY,
  action TEXT NOT NULL,
  project TEXT NOT NULL DEFAULT 'default',
  env TEXT NOT NULL DEFAULT '',
  target_host TEXT NOT NULL DEFAULT '',
  args_json TEXT NOT NULL,
  actor TEXT NOT NULL,
  requires_approval INTEGER NOT NULL,
  status TEXT NOT NULL,
  approver TEXT NOT NULL DEFAULT '',
  result TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_approval_status_created ON approval_requests(status, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_approval_project_status_created ON approval_requests(project, status, created_at DESC);
`)
	if err != nil {
		return err
	}
	_, err = db.Exec(`ALTER TABLE approval_requests ADD COLUMN env TEXT NOT NULL DEFAULT ''`)
	if err != nil && !strings.Contains(strings.ToLower(err.Error()), "duplicate column name") {
		return err
	}
	_, err = db.Exec(`ALTER TABLE approval_requests ADD COLUMN project TEXT NOT NULL DEFAULT 'default'`)
	if err != nil && !strings.Contains(strings.ToLower(err.Error()), "duplicate column name") {
		return err
	}
	_, err = db.Exec(`ALTER TABLE approval_requests ADD COLUMN target_host TEXT NOT NULL DEFAULT ''`)
	if err != nil && !strings.Contains(strings.ToLower(err.Error()), "duplicate column name") {
		return err
	}
	return nil
}

func (s SQLiteStore) Create(r Request) error {
	db, err := s.open()
	if err != nil {
		return err
	}
	defer db.Close()
	argsJSON, err := marshalArgs(r.Args)
	if err != nil {
		return err
	}
	_, err = db.Exec(`
INSERT INTO approval_requests(id, action, project, env, target_host, args_json, actor, requires_approval, status, approver, result, created_at, updated_at)
VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
`, r.ID, r.Action, normalizeProject(r.Project), r.Env, r.TargetHost, argsJSON, r.Actor, boolToInt(r.RequiresApproval), r.Status, r.Approver, r.Result, r.CreatedAt.UTC().Format(time.RFC3339Nano), r.UpdatedAt.UTC().Format(time.RFC3339Nano))
	return err
}

func (s SQLiteStore) Update(id string, update func(*Request) error) (Request, error) {
	db, err := s.open()
	if err != nil {
		return Request{}, err
	}
	defer db.Close()

	r, err := s.getByID(db, id)
	if err != nil {
		return Request{}, err
	}
	if err := update(&r); err != nil {
		return Request{}, err
	}
	r.UpdatedAt = time.Now().UTC()
	argsJSON, err := marshalArgs(r.Args)
	if err != nil {
		return Request{}, err
	}
	_, err = db.Exec(`
UPDATE approval_requests
SET action=?, project=?, env=?, target_host=?, args_json=?, actor=?, requires_approval=?, status=?, approver=?, result=?, updated_at=?
WHERE id=?
`, r.Action, normalizeProject(r.Project), r.Env, r.TargetHost, argsJSON, r.Actor, boolToInt(r.RequiresApproval), r.Status, r.Approver, r.Result, r.UpdatedAt.UTC().Format(time.RFC3339Nano), r.ID)
	if err != nil {
		return Request{}, err
	}
	return r, nil
}

func (s SQLiteStore) GetByID(id string) (Request, error) {
	db, err := s.open()
	if err != nil {
		return Request{}, err
	}
	defer db.Close()
	return s.getByID(db, id)
}

func (s SQLiteStore) ListPending(limit int, projects []string) ([]Request, error) {
	return s.ListByStatus("pending", limit, projects)
}

func (s SQLiteStore) ListByStatus(status string, limit int, projects []string) ([]Request, error) {
	db, err := s.open()
	if err != nil {
		return nil, err
	}
	defer db.Close()
	if limit <= 0 {
		limit = 50
	}
	query := `
SELECT id, action, project, env, target_host, args_json, actor, requires_approval, status, approver, result, created_at, updated_at
FROM approval_requests
WHERE status=?
`
	args := []any{status}
	if len(projects) > 0 {
		query += " AND project IN (" + placeholders(len(projects)) + ")"
		for _, project := range projects {
			args = append(args, normalizeProject(project))
		}
	}
	query += `
ORDER BY created_at DESC
LIMIT ?
`
	args = append(args, limit)
	rows, err := db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]Request, 0, limit)
	for rows.Next() {
		r, err := scanRequest(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	return out, nil
}

func (s SQLiteStore) ExpirePendingOlderThan(ttl time.Duration) (int64, error) {
	if ttl <= 0 {
		return 0, nil
	}
	db, err := s.open()
	if err != nil {
		return 0, err
	}
	defer db.Close()
	cutoff := time.Now().UTC().Add(-ttl).Format(time.RFC3339Nano)
	res, err := db.Exec(`
UPDATE approval_requests
SET status='expired', result='expired by ttl', updated_at=?
WHERE status='pending' AND created_at < ?
`, time.Now().UTC().Format(time.RFC3339Nano), cutoff)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

func (s SQLiteStore) getByID(db *sql.DB, id string) (Request, error) {
	row := db.QueryRow(`
SELECT id, action, project, env, target_host, args_json, actor, requires_approval, status, approver, result, created_at, updated_at
FROM approval_requests
WHERE id=?
`, id)
	r, err := scanRequest(row)
	if err != nil {
		if err == sql.ErrNoRows {
			return Request{}, fmt.Errorf("request not found: %s", id)
		}
		return Request{}, err
	}
	return r, nil
}

type scanner interface {
	Scan(dest ...any) error
}

func scanRequest(s scanner) (Request, error) {
	var r Request
	var argsJSON string
	var reqInt int
	var created, updated string
	if err := s.Scan(&r.ID, &r.Action, &r.Project, &r.Env, &r.TargetHost, &argsJSON, &r.Actor, &reqInt, &r.Status, &r.Approver, &r.Result, &created, &updated); err != nil {
		return Request{}, err
	}
	args, err := unmarshalArgs(argsJSON)
	if err != nil {
		return Request{}, err
	}
	r.Args = args
	r.RequiresApproval = reqInt == 1
	r.Project = normalizeProject(r.Project)
	r.CreatedAt, _ = time.Parse(time.RFC3339Nano, created)
	r.UpdatedAt, _ = time.Parse(time.RFC3339Nano, updated)
	return r, nil
}

func boolToInt(v bool) int {
	if v {
		return 1
	}
	return 0
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
