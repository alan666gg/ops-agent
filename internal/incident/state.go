package incident

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

type Record struct {
	ID              string           `json:"id"`
	Source          string           `json:"source"`
	Key             string           `json:"key,omitempty"`
	Project         string           `json:"project,omitempty"`
	Env             string           `json:"env"`
	Status          string           `json:"status"`
	Summary         string           `json:"summary"`
	Fingerprint     string           `json:"fingerprint"`
	Highlights      []string         `json:"highlights,omitempty"`
	Open            bool             `json:"open"`
	Acknowledged    bool             `json:"acknowledged"`
	AcknowledgedBy  string           `json:"acknowledged_by,omitempty"`
	AcknowledgedAt  time.Time        `json:"acknowledged_at,omitempty"`
	Owner           string           `json:"owner,omitempty"`
	Note            string           `json:"note,omitempty"`
	FirstSeenAt     time.Time        `json:"first_seen_at,omitempty"`
	LastSeenAt      time.Time        `json:"last_seen_at,omitempty"`
	LastChangedAt   time.Time        `json:"last_changed_at,omitempty"`
	ClosedAt        time.Time        `json:"closed_at,omitempty"`
	UpdatedAt       time.Time        `json:"updated_at,omitempty"`
	FailCount       int              `json:"fail_count"`
	WarnCount       int              `json:"warn_count"`
	SuppressedCount int              `json:"suppressed_count"`
	External        *ExternalAlert   `json:"external,omitempty"`
	Silence         *ExternalSilence `json:"silence,omitempty"`
}

type Filter struct {
	Projects []string
	Env      string
	Source   string
	OpenOnly bool
	Limit    int
}

type Store interface {
	SyncReport(report Report, now time.Time) (Record, error)
	Get(id string) (Record, bool, error)
	List(filter Filter) ([]Record, error)
	Ack(id, actor, note string, now time.Time) (Record, error)
	Assign(id, owner, actor, note string, now time.Time) (Record, error)
	SetSilence(id string, silence ExternalSilence, now time.Time) (Record, error)
	ExpireSilence(id, actor, note string, now time.Time) (Record, error)
}

type MemoryStore struct {
	items map[string]Record
}

func (m *MemoryStore) SyncReport(report Report, now time.Time) (Record, error) {
	rec, ok, err := m.Get(recordID(report))
	if err != nil {
		return Record{}, err
	}
	next := syncRecord(rec, ok, report, now)
	if m.items == nil {
		m.items = map[string]Record{}
	}
	m.items[next.ID] = next
	return next, nil
}

func (m *MemoryStore) Get(id string) (Record, bool, error) {
	if m.items == nil {
		m.items = map[string]Record{}
	}
	rec, ok := m.items[strings.TrimSpace(id)]
	return rec, ok, nil
}

func (m *MemoryStore) List(filter Filter) ([]Record, error) {
	if m.items == nil {
		return nil, nil
	}
	out := make([]Record, 0, len(m.items))
	for _, rec := range m.items {
		if matchesFilter(rec, filter) {
			out = append(out, rec)
		}
	}
	sortRecords(out)
	if filter.Limit > 0 && len(out) > filter.Limit {
		out = out[:filter.Limit]
	}
	return out, nil
}

func (m *MemoryStore) Ack(id, actor, note string, now time.Time) (Record, error) {
	rec, ok, err := m.Get(id)
	if err != nil {
		return Record{}, err
	}
	if !ok {
		return Record{}, fmt.Errorf("incident not found: %s", id)
	}
	rec.Acknowledged = true
	rec.AcknowledgedBy = strings.TrimSpace(actor)
	rec.AcknowledgedAt = now.UTC()
	if note = strings.TrimSpace(note); note != "" {
		rec.Note = note
	}
	rec.UpdatedAt = now.UTC()
	m.items[rec.ID] = rec
	return rec, nil
}

func (m *MemoryStore) Assign(id, owner, actor, note string, now time.Time) (Record, error) {
	rec, ok, err := m.Get(id)
	if err != nil {
		return Record{}, err
	}
	if !ok {
		return Record{}, fmt.Errorf("incident not found: %s", id)
	}
	rec.Owner = strings.TrimSpace(owner)
	if note = strings.TrimSpace(note); note != "" {
		if strings.TrimSpace(actor) != "" {
			rec.Note = fmt.Sprintf("%s (by %s)", note, strings.TrimSpace(actor))
		} else {
			rec.Note = note
		}
	}
	rec.UpdatedAt = now.UTC()
	m.items[rec.ID] = rec
	return rec, nil
}

func (m *MemoryStore) SetSilence(id string, silence ExternalSilence, now time.Time) (Record, error) {
	rec, ok, err := m.Get(id)
	if err != nil {
		return Record{}, err
	}
	if !ok {
		return Record{}, fmt.Errorf("incident not found: %s", id)
	}
	silence.Status = strings.TrimSpace(silence.Status)
	if silence.Status == "" {
		silence.Status = "active"
	}
	silence.UpdatedAt = now.UTC()
	rec.Silence = cloneExternalSilence(&silence)
	rec.UpdatedAt = now.UTC()
	m.items[rec.ID] = rec
	return rec, nil
}

func (m *MemoryStore) ExpireSilence(id, actor, note string, now time.Time) (Record, error) {
	rec, ok, err := m.Get(id)
	if err != nil {
		return Record{}, err
	}
	if !ok {
		return Record{}, fmt.Errorf("incident not found: %s", id)
	}
	if rec.Silence == nil {
		return Record{}, fmt.Errorf("incident has no silence: %s", id)
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
	m.items[rec.ID] = rec
	return rec, nil
}

func recordID(report Report) string {
	parts := []string{
		strings.TrimSpace(report.Source),
		defaultProject(report.Project),
		strings.TrimSpace(report.Env),
	}
	if key := strings.TrimSpace(report.Key); key != "" {
		parts = append(parts, key)
	}
	return strings.Join(parts, "|")
}

func syncRecord(prev Record, ok bool, report Report, now time.Time) Record {
	now = now.UTC()
	currentOpen := IsActionableStatus(report.Status)
	next := prev
	if !ok {
		next = Record{
			ID:          recordID(report),
			Source:      strings.TrimSpace(report.Source),
			Key:         strings.TrimSpace(report.Key),
			Project:     defaultProject(report.Project),
			Env:         strings.TrimSpace(report.Env),
			FirstSeenAt: now,
		}
	}
	next.Source = strings.TrimSpace(report.Source)
	next.Key = strings.TrimSpace(report.Key)
	next.Project = defaultProject(report.Project)
	next.Env = strings.TrimSpace(report.Env)
	next.Status = strings.TrimSpace(report.Status)
	next.Summary = strings.TrimSpace(report.Summary)
	next.Fingerprint = strings.TrimSpace(report.Fingerprint)
	next.Highlights = append([]string(nil), report.Highlights...)
	next.External = cloneExternalAlert(report.External)
	next.Silence = cloneExternalSilence(prev.Silence)
	next.FailCount = report.FailCount
	next.WarnCount = report.WarnCount
	next.SuppressedCount = report.SuppressedCount
	next.LastSeenAt = now
	next.UpdatedAt = now
	changed := !ok || prev.Status != next.Status || prev.Fingerprint != next.Fingerprint

	switch {
	case currentOpen && !prev.Open:
		next.Open = true
		next.ClosedAt = time.Time{}
		next.FirstSeenAt = now
		next.LastChangedAt = now
		next.Acknowledged = false
		next.AcknowledgedBy = ""
		next.AcknowledgedAt = time.Time{}
		next.Owner = ""
		next.Note = ""
	case currentOpen && prev.Open:
		next.Open = true
		next.ClosedAt = time.Time{}
		if changed {
			next.LastChangedAt = now
			next.Acknowledged = false
			next.AcknowledgedBy = ""
			next.AcknowledgedAt = time.Time{}
		}
	case !currentOpen && prev.Open:
		next.Open = false
		next.ClosedAt = now
		next.LastChangedAt = now
	default:
		next.Open = false
		if changed {
			next.LastChangedAt = now
		}
	}
	if next.LastChangedAt.IsZero() {
		next.LastChangedAt = now
	}
	return next
}

func cloneExternalAlert(v *ExternalAlert) *ExternalAlert {
	if v == nil {
		return nil
	}
	out := *v
	if len(v.Labels) > 0 {
		out.Labels = make(map[string]string, len(v.Labels))
		for key, value := range v.Labels {
			out.Labels[key] = value
		}
	}
	if len(v.Annotations) > 0 {
		out.Annotations = make(map[string]string, len(v.Annotations))
		for key, value := range v.Annotations {
			out.Annotations[key] = value
		}
	}
	return &out
}

func cloneExternalSilence(v *ExternalSilence) *ExternalSilence {
	if v == nil {
		return nil
	}
	out := *v
	return &out
}

func matchesFilter(rec Record, filter Filter) bool {
	if filter.OpenOnly && !rec.Open {
		return false
	}
	if strings.TrimSpace(filter.Env) != "" && !strings.EqualFold(strings.TrimSpace(filter.Env), strings.TrimSpace(rec.Env)) {
		return false
	}
	if strings.TrimSpace(filter.Source) != "" && !strings.EqualFold(strings.TrimSpace(filter.Source), strings.TrimSpace(rec.Source)) {
		return false
	}
	if len(filter.Projects) > 0 {
		project := defaultProject(rec.Project)
		match := false
		for _, allowed := range filter.Projects {
			if strings.EqualFold(project, defaultProject(allowed)) {
				match = true
				break
			}
		}
		if !match {
			return false
		}
	}
	return true
}

func sortRecords(items []Record) {
	sort.SliceStable(items, func(i, j int) bool {
		ri := severityRank(items[i].Status)
		rj := severityRank(items[j].Status)
		if ri == rj {
			if items[i].Open == items[j].Open {
				return items[i].LastChangedAt.After(items[j].LastChangedAt)
			}
			return items[i].Open
		}
		return ri > rj
	})
}

func defaultProject(project string) string {
	project = strings.TrimSpace(project)
	if project == "" {
		return "default"
	}
	return project
}

func severityRank(status string) int {
	switch strings.ToLower(strings.TrimSpace(status)) {
	case "fail":
		return 2
	case "warn":
		return 1
	default:
		return 0
	}
}

func IsActionableStatus(status string) bool {
	return severityRank(status) > 0
}
