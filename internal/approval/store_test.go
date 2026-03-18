package approval

import (
	"path/filepath"
	"testing"
	"time"
)

func TestJSONStoreLifecycle(t *testing.T) {
	d := t.TempDir()
	s := Store{Path: filepath.Join(d, "pending.json")}
	now := time.Now().UTC()
	err := s.Create(Request{ID: "r1", Action: "restart_container", Args: []string{"app"}, Actor: "dev", RequiresApproval: true, Status: "pending", CreatedAt: now, UpdatedAt: now})
	if err != nil {
		t.Fatal(err)
	}
	items, err := s.ListPending(10)
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 1 || items[0].ID != "r1" {
		t.Fatalf("unexpected pending: %+v", items)
	}
	_, err = s.Update("r1", func(r *Request) error { r.Status = "approved"; return nil })
	if err != nil {
		t.Fatal(err)
	}
	items, err = s.ListByStatus("approved", 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 1 || items[0].Status != "approved" {
		t.Fatalf("unexpected approved: %+v", items)
	}
}

func TestSQLiteStoreExpirePending(t *testing.T) {
	d := t.TempDir()
	s := SQLiteStore{Path: filepath.Join(d, "pending.db")}
	old := time.Now().UTC().Add(-2 * time.Hour)
	err := s.Create(Request{ID: "r-old", Action: "restart_container", Args: []string{"app"}, Actor: "dev", RequiresApproval: true, Status: "pending", CreatedAt: old, UpdatedAt: old})
	if err != nil {
		t.Fatal(err)
	}
	changed, err := s.ExpirePendingOlderThan(1 * time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if changed != 1 {
		t.Fatalf("expected 1 changed, got %d", changed)
	}
	items, err := s.ListByStatus("expired", 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 1 || items[0].ID != "r-old" {
		t.Fatalf("unexpected expired items: %+v", items)
	}
}
