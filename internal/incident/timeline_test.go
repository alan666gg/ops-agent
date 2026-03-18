package incident

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/alan666gg/ops-agent/internal/audit"
)

func TestTimelineBuilderCorrelatesChangesNearIncidentStart(t *testing.T) {
	now := time.Date(2026, 3, 18, 10, 30, 0, 0, time.UTC)
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	for _, evt := range []audit.Event{
		{Time: now.Add(-20 * time.Minute), Actor: "tg:@ops", Action: "restart_container", Project: "core", Env: "prod", TargetHost: "app-1", Status: "ok", Message: "manual restart"},
		{Time: now.Add(-10 * time.Minute), Actor: "ops-scheduler", Action: "health_run", Project: "core", Env: "prod", Target: "prod/service_api", Status: "failed", Message: "HTTP_DOWN: connection refused"},
		{Time: now.Add(-5 * time.Minute), Actor: "tg:@lead", Action: "incident_ack", Project: "core", Env: "prod", Target: "ops-scheduler|core|prod", Status: "ok", Message: "investigating"},
		{Time: now.Add(2 * time.Minute), Actor: "ops-api", Action: "notify", Project: "core", Env: "prod", Status: "ok", Message: "should be filtered"},
	} {
		if err := audit.AppendJSONL(path, evt); err != nil {
			t.Fatal(err)
		}
	}

	record := Record{
		ID:          "ops-scheduler|core|prod",
		Project:     "core",
		Env:         "prod",
		Status:      "fail",
		FirstSeenAt: now,
		LastSeenAt:  now.Add(5 * time.Minute),
	}
	timeline, err := (TimelineBuilder{Store: audit.JSONLStore{Path: path}, Now: func() time.Time { return now }}).Build(record, 60*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if len(timeline.Entries) != 3 {
		t.Fatalf("expected notify event to be filtered, got %+v", timeline.Entries)
	}
	if got := timeline.Entries[0].Action; got != "restart_container" {
		t.Fatalf("expected entries sorted ascending, got first action %q", got)
	}
	if len(timeline.CorrelatedChanges) != 1 {
		t.Fatalf("expected one correlated change, got %+v", timeline.CorrelatedChanges)
	}
	if !timeline.CorrelatedChanges[0].LikelyChange || timeline.CorrelatedChanges[0].Kind != "change" {
		t.Fatalf("unexpected correlated change entry: %+v", timeline.CorrelatedChanges[0])
	}
}
