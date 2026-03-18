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
		{Time: now.Add(-10 * time.Minute), Action: "check_host_health", Env: "prod", Status: "ok"},
		{Time: now.Add(-9 * time.Minute), Action: "check_host_health", Env: "prod", Status: "pending"},
		{Time: now.Add(-8 * time.Minute), Action: "restart_container", Env: "prod", Status: "executed", RequiresOK: true},
		{Time: now.Add(-7 * time.Minute), Action: "check_service_health", Env: "test", Status: "ok"},
		{Time: now.Add(-2 * time.Hour), Action: "check_dependencies", Env: "prod", Status: "ok"},
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
}
