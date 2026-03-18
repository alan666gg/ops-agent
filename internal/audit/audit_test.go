package audit

import (
	"path/filepath"
	"testing"
	"time"
)

func TestCountRecentAutoActions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "events.jsonl")
	now := time.Now().UTC()
	events := []Event{
		{Time: now.Add(-10 * time.Minute), Action: "check_host_health", Project: "payments", Env: "prod", Status: "ok"},
		{Time: now.Add(-9 * time.Minute), Action: "check_host_health", Project: "payments", Env: "prod", Status: "pending"},
		{Time: now.Add(-8 * time.Minute), Action: "restart_container", Project: "payments", Env: "prod", Status: "executed", RequiresOK: true},
		{Time: now.Add(-7 * time.Minute), Action: "check_service_health", Project: "search", Env: "test", Status: "ok"},
		{Time: now.Add(-2 * time.Hour), Action: "check_dependencies", Project: "payments", Env: "prod", Status: "ok"},
	}

	for _, evt := range events {
		if err := AppendJSONL(path, evt); err != nil {
			t.Fatal(err)
		}
	}

	count, err := CountRecentAutoActions(path, "prod", now.Add(-1*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("expected 1 recent auto action, got %d", count)
	}

	count, err = CountRecentAutoActionsByProject(path, "payments", "prod", now.Add(-1*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("expected 1 recent auto action for project filter, got %d", count)
	}
}

func TestSQLiteStoreListByProject(t *testing.T) {
	store := SQLiteStore{Path: filepath.Join(t.TempDir(), "audit.db")}
	now := time.Now().UTC()
	for _, evt := range []Event{
		{Time: now.Add(-2 * time.Minute), Action: "health_cycle", Project: "payments", Env: "prod", Status: "fail", Target: "prod/service_api"},
		{Time: now.Add(-1 * time.Minute), Action: "health_cycle", Project: "search", Env: "prod", Status: "ok", Target: "prod/service_search"},
	} {
		if err := store.Append(evt); err != nil {
			t.Fatal(err)
		}
	}
	events, err := store.List(Query{Projects: []string{"payments"}, Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 || events[0].Project != "payments" {
		t.Fatalf("unexpected sqlite project-filtered events: %+v", events)
	}
}
