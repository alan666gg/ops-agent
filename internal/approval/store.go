package approval

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"time"
)

type Request struct {
	ID               string    `json:"id"`
	Action           string    `json:"action"`
	Env              string    `json:"env,omitempty"`
	TargetHost       string    `json:"target_host,omitempty"`
	Args             []string  `json:"args"`
	Actor            string    `json:"actor"`
	RequiresApproval bool      `json:"requires_approval"`
	Status           string    `json:"status"` // pending|approved|executed|failed|denied
	Approver         string    `json:"approver,omitempty"`
	Result           string    `json:"result,omitempty"`
	CreatedAt        time.Time `json:"created_at"`
	UpdatedAt        time.Time `json:"updated_at"`
}

type Store struct {
	Path string
}

func (s Store) load() ([]Request, error) {
	b, err := os.ReadFile(s.Path)
	if err != nil {
		if os.IsNotExist(err) {
			return []Request{}, nil
		}
		return nil, err
	}
	if len(b) == 0 {
		return []Request{}, nil
	}
	var items []Request
	if err := json.Unmarshal(b, &items); err != nil {
		return nil, err
	}
	return items, nil
}

func (s Store) save(items []Request) error {
	if err := os.MkdirAll("audit", 0o755); err != nil {
		return err
	}
	b, err := json.MarshalIndent(items, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(s.Path, b, 0o644)
}

func (s Store) Create(r Request) error {
	items, err := s.load()
	if err != nil {
		return err
	}
	items = append(items, r)
	return s.save(items)
}

func (s Store) Update(id string, update func(*Request) error) (Request, error) {
	items, err := s.load()
	if err != nil {
		return Request{}, err
	}
	for i := range items {
		if items[i].ID == id {
			if err := update(&items[i]); err != nil {
				return Request{}, err
			}
			items[i].UpdatedAt = time.Now().UTC()
			if err := s.save(items); err != nil {
				return Request{}, err
			}
			return items[i], nil
		}
	}
	return Request{}, fmt.Errorf("request not found: %s", id)
}

func (s Store) ListPending(limit int) ([]Request, error) {
	return s.ListByStatus("pending", limit)
}

func (s Store) ListByStatus(status string, limit int) ([]Request, error) {
	items, err := s.load()
	if err != nil {
		return nil, err
	}
	out := make([]Request, 0)
	for _, it := range items {
		if it.Status == status {
			out = append(out, it)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

func (s Store) ExpirePendingOlderThan(ttl time.Duration) (int64, error) {
	if ttl <= 0 {
		return 0, nil
	}
	items, err := s.load()
	if err != nil {
		return 0, err
	}
	cutoff := time.Now().UTC().Add(-ttl)
	var changed int64
	for i := range items {
		if items[i].Status == "pending" && items[i].CreatedAt.Before(cutoff) {
			items[i].Status = "expired"
			items[i].Result = "expired by ttl"
			items[i].UpdatedAt = time.Now().UTC()
			changed++
		}
	}
	if changed > 0 {
		if err := s.save(items); err != nil {
			return 0, err
		}
	}
	return changed, nil
}
