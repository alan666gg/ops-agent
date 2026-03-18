package audit

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/alan666gg/ops-agent/internal/actions"
)

type Event struct {
	Time       time.Time `json:"time"`
	Actor      string    `json:"actor"`
	Action     string    `json:"action"`
	Project    string    `json:"project,omitempty"`
	Env        string    `json:"env,omitempty"`
	TargetHost string    `json:"target_host,omitempty"`
	Target     string    `json:"target,omitempty"`
	Status     string    `json:"status"`
	Message    string    `json:"message,omitempty"`
	RequiresOK bool      `json:"requires_approval,omitempty"`
}

type Query struct {
	Since    time.Time
	Projects []string
	Env      string
	Actions  []string
	Limit    int
}

type Store interface {
	Append(Event) error
	CountRecentAutoActions(project, env string, since time.Time) (int, error)
	List(Query) ([]Event, error)
	Driver() string
	Location() string
}

type JSONLStore struct {
	Path string
}

func Open(driver, path string) (Store, error) {
	switch strings.ToLower(strings.TrimSpace(driver)) {
	case "", "jsonl", "json":
		return JSONLStore{Path: path}, nil
	case "sqlite":
		return SQLiteStore{Path: path}, nil
	default:
		return nil, fmt.Errorf("unsupported audit driver: %s", driver)
	}
}

func AppendJSONL(path string, evt Event) error {
	return JSONLStore{Path: path}.Append(evt)
}

func CountRecentAutoActions(path, env string, since time.Time) (int, error) {
	return JSONLStore{Path: path}.CountRecentAutoActions("", env, since)
}

func CountRecentAutoActionsByProject(path, project, env string, since time.Time) (int, error) {
	return JSONLStore{Path: path}.CountRecentAutoActions(project, env, since)
}

func RecentEvents(path string, q Query) ([]Event, error) {
	return JSONLStore{Path: path}.List(q)
}

func (s JSONLStore) Driver() string {
	return "jsonl"
}

func (s JSONLStore) Location() string {
	return s.Path
}

func (s JSONLStore) Append(evt Event) error {
	f, err := os.OpenFile(s.Path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	return enc.Encode(evt)
}

func (s JSONLStore) CountRecentAutoActions(project, env string, since time.Time) (int, error) {
	events, err := s.List(Query{
		Since:    since,
		Projects: normalizeProjects(project),
		Env:      env,
		Limit:    0,
	})
	if err != nil {
		return 0, err
	}
	count := 0
	for _, evt := range events {
		if evt.RequiresOK {
			continue
		}
		if !countableAction(evt) {
			continue
		}
		count++
	}
	return count, nil
}

func (s JSONLStore) List(q Query) ([]Event, error) {
	f, err := os.Open(s.Path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	defer f.Close()

	out := make([]Event, 0)
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		var evt Event
		if err := json.Unmarshal(sc.Bytes(), &evt); err != nil {
			continue
		}
		if !matchesQuery(evt, q) {
			continue
		}
		out = append(out, evt)
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	sort.SliceStable(out, func(i, j int) bool {
		return out[i].Time.After(out[j].Time)
	})
	if q.Limit > 0 && len(out) > q.Limit {
		out = out[:q.Limit]
	}
	return out, nil
}

func normalizeProjects(project string) []string {
	project = strings.TrimSpace(project)
	if project == "" {
		return nil
	}
	return []string{project}
}

func matchesQuery(evt Event, q Query) bool {
	if !q.Since.IsZero() && evt.Time.Before(q.Since) {
		return false
	}
	if len(q.Projects) > 0 {
		project := defaultProject(evt.Project)
		matched := false
		for _, allowed := range q.Projects {
			if strings.EqualFold(project, defaultProject(allowed)) {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}
	if strings.TrimSpace(q.Env) != "" && !strings.EqualFold(strings.TrimSpace(evt.Env), strings.TrimSpace(q.Env)) {
		return false
	}
	if len(q.Actions) > 0 {
		matched := false
		for _, action := range q.Actions {
			if strings.EqualFold(strings.TrimSpace(evt.Action), strings.TrimSpace(action)) {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}
	return true
}

func countableAction(evt Event) bool {
	if _, ok := actions.Lookup(evt.Action); !ok {
		return false
	}
	switch evt.Status {
	case "ok", "failed", "executed":
		return true
	default:
		return false
	}
}

func defaultProject(project string) string {
	project = strings.TrimSpace(project)
	if project == "" {
		return "default"
	}
	return project
}
