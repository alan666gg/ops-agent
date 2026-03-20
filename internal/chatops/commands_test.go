package chatops

import (
	"strings"
	"testing"
	"time"

	"github.com/alan666gg/ops-agent/internal/approval"
	"github.com/alan666gg/ops-agent/internal/checks"
	"github.com/alan666gg/ops-agent/internal/incident"
	promapi "github.com/alan666gg/ops-agent/internal/prometheus"
)

func TestParseCommandHealthAndRequest(t *testing.T) {
	cmd, err := ParseCommand("/health prod")
	if err != nil {
		t.Fatal(err)
	}
	if cmd.Name != "health" || cmd.Env != "prod" {
		t.Fatalf("unexpected health command: %+v", cmd)
	}

	cmd, err = ParseCommand("/request prod restart_container --target-host=app-1 api-1")
	if err != nil {
		t.Fatal(err)
	}
	if cmd.Name != "request" || cmd.Env != "prod" || cmd.Action != "restart_container" || cmd.TargetHost != "app-1" {
		t.Fatalf("unexpected request command: %+v", cmd)
	}
	if len(cmd.Args) != 1 || cmd.Args[0] != "api-1" {
		t.Fatalf("unexpected request args: %+v", cmd.Args)
	}

	cmd, err = ParseCommand("/reset")
	if err != nil {
		t.Fatal(err)
	}
	if cmd.Name != "reset" {
		t.Fatalf("unexpected reset command: %+v", cmd)
	}

	cmd, err = ParseCommand("/show r1")
	if err != nil {
		t.Fatal(err)
	}
	if cmd.Name != "show" || cmd.RequestID != "r1" {
		t.Fatalf("unexpected show command: %+v", cmd)
	}

	cmd, err = ParseCommand("/ack ops-scheduler|core|prod taking ownership")
	if err != nil {
		t.Fatal(err)
	}
	if cmd.Name != "ack" || cmd.IncidentID != "ops-scheduler|core|prod" {
		t.Fatalf("unexpected ack command: %+v", cmd)
	}

	cmd, err = ParseCommand("/unsilence ops-scheduler|core|prod resume notifications")
	if err != nil {
		t.Fatal(err)
	}
	if cmd.Name != "unsilence" || cmd.IncidentID != "ops-scheduler|core|prod" {
		t.Fatalf("unexpected unsilence command: %+v", cmd)
	}

	cmd, err = ParseCommand("/assign ops-scheduler|core|prod alice on it")
	if err != nil {
		t.Fatal(err)
	}
	if cmd.Name != "assign" || cmd.IncidentID != "ops-scheduler|core|prod" || cmd.Owner != "alice" {
		t.Fatalf("unexpected assign command: %+v", cmd)
	}

	cmd, err = ParseCommand("/timeline ops-scheduler|core|prod 120")
	if err != nil {
		t.Fatal(err)
	}
	if cmd.Name != "timeline" || cmd.IncidentID != "ops-scheduler|core|prod" || cmd.Minutes != 120 {
		t.Fatalf("unexpected timeline command: %+v", cmd)
	}

	cmd, err = ParseCommand("/promql prod --minutes=30 --step=60s avg(rate(http_requests_total[5m]))")
	if err != nil {
		t.Fatal(err)
	}
	if cmd.Name != "promql" || cmd.Env != "prod" || cmd.Minutes != 30 || cmd.Step != time.Minute || cmd.Query != "avg(rate(http_requests_total[5m]))" {
		t.Fatalf("unexpected promql command: %+v", cmd)
	}

	cmd, err = ParseCommand("/stats prod")
	if err != nil {
		t.Fatal(err)
	}
	if cmd.Name != "stats" || cmd.Env != "prod" {
		t.Fatalf("unexpected stats command: %+v", cmd)
	}

	cmd, err = ParseCommand("/changes prod 180")
	if err != nil {
		t.Fatal(err)
	}
	if cmd.Name != "changes" || cmd.Env != "prod" || cmd.Minutes != 180 {
		t.Fatalf("unexpected changes command: %+v", cmd)
	}

	cmd, err = ParseCommand("/changes 45")
	if err != nil {
		t.Fatal(err)
	}
	if cmd.Name != "changes" || cmd.Env != "" || cmd.Minutes != 45 {
		t.Fatalf("unexpected changes shortcut command: %+v", cmd)
	}
}

func TestParseCommandRejectRequiresRequestID(t *testing.T) {
	if _, err := ParseCommand("/reject"); err == nil {
		t.Fatal("expected reject validation error")
	}
}

func TestFormatHealthIncludesSuppressedAndSuggestions(t *testing.T) {
	text := FormatHealth(HealthResponse{
		Status:  "fail",
		Summary: "ops-api prod: 1 failed",
		Highlights: []string{
			"service_runtime_api [CONTAINER_OOMKILLED] oom_killed=true exit_code=137",
		},
		RecentChanges: []incident.TimelineEntry{
			{Time: stringsToTime(t, "2026-03-18T10:00:00Z"), Kind: "change", Action: "deploy_event", Reference: "v2026.03.20", Revision: "abcdef123456", Target: "service/api"},
		},
		MetricSignals: []promapi.SignalObservation{
			{Name: "host_cpu_hot", Scope: "host", Subject: "app-1", Strategy: "capacity", Comparator: "above", Threshold: 2, Value: 2.7},
		},
		Results: []checks.Result{
			{Name: "host_ssh_app_1", Code: "TCP_UNREACHABLE", Severity: checks.SeverityFail, Message: "connection refused"},
		},
		SuppressedChecks: []incident.SuppressedCheck{
			{Result: checks.Result{Name: "service_api"}, SuppressedBy: "host_ssh_app_1"},
		},
		Suggestions: []incident.Suggestion{
			{Action: "check_host_health", TargetHost: "app-1", Strategy: "capacity"},
		},
	})
	for _, want := range []string{"[FAIL]", "highlight service_runtime_api [CONTAINER_OOMKILLED]", "metric host_cpu_hot host app-1", "recent_change 10:00 change deploy_event", "host_ssh_app_1 [TCP_UNREACHABLE]", "suppressed service_api", "suggest check_host_health target=app-1 strategy=capacity"} {
		if !strings.Contains(text, want) {
			t.Fatalf("expected %q in %q", want, text)
		}
	}
}

func TestFormatPrometheusQuery(t *testing.T) {
	text := FormatPrometheusQuery(PrometheusQueryResponse{
		Project: "core",
		Env:     "prod",
		Data: promapi.QueryResponse{
			Query:      "up",
			ResultType: "vector",
			Summary:    "vector query returned 1 series; top=instance=app-1:9100,job=node value=1",
			Series: []promapi.Series{
				{
					Metric: map[string]string{"job": "node", "instance": "app-1:9100"},
					Value:  &promapi.Sample{Time: stringsToTime(t, "2026-03-18T10:05:00Z"), Value: "1"},
				},
			},
		},
	})
	for _, want := range []string{"prometheus env=prod project=core", "query=up", "result_type=vector", "instance=app-1:9100"} {
		if !strings.Contains(text, want) {
			t.Fatalf("expected %q in %q", want, text)
		}
	}
}

func TestFormatPending(t *testing.T) {
	text := FormatPending(PendingResponse{
		Count: 1,
		Items: []approval.Request{
			{ID: "r1", Action: "restart_container", Env: "prod", Args: []string{"api-1"}, Actor: "tg:@ops"},
		},
	})
	for _, want := range []string{"r1 restart_container", "project=default", "env=prod"} {
		if !strings.Contains(text, want) {
			t.Fatalf("unexpected pending text: %s", text)
		}
	}
}

func TestFormatIncidentSummaryIncludesProjects(t *testing.T) {
	text := FormatIncidentSummary(IncidentSummary{
		WindowMinutes: 60,
		Projects:      []string{"payments"},
		Total:         3,
		ByStatus:      map[string]int{"fail": 2, "warn": 1},
	})
	if !strings.Contains(text, "projects: payments") {
		t.Fatalf("unexpected pending text: %s", text)
	}
}

func TestFormatIncidentStats(t *testing.T) {
	text := FormatIncidentStats(IncidentStatsResponse{
		Projects: []string{"core"},
		Env:      "prod",
		Summary: incident.Stats{
			TotalRecords:         3,
			OpenRecords:          1,
			ResolvedRecords:      2,
			AcknowledgedRecords:  1,
			AssignedRecords:      1,
			SilencedRecords:      0,
			ReopenCount:          1,
			ResolutionCount:      2,
			AckCount:             1,
			AvgMTTASeconds:       60,
			AvgMTTRSeconds:       300,
			OldestOpenAgeSeconds: 120,
		},
	})
	for _, want := range []string{"incident stats", "total=3 open=1 resolved=2", "avg_mtta=60.0s avg_mttr=300.0s", "projects=core"} {
		if !strings.Contains(text, want) {
			t.Fatalf("expected %q in %q", want, text)
		}
	}
}

func TestFormatRecentChanges(t *testing.T) {
	text := FormatRecentChanges(RecentChangesResponse{
		WindowMinutes: 120,
		Projects:      []string{"core"},
		Env:           "prod",
		Count:         1,
		Items: []incident.TimelineEntry{
			{Time: stringsToTime(t, "2026-03-18T10:00:00Z"), Kind: "change", Action: "deploy_release", Status: "ok", Actor: "ci:github-actions", Target: "service/api", Reference: "v2026.03.20", Revision: "abcdef123456", URL: "https://ci.example/run/1"},
		},
	})
	for _, want := range []string{"recent changes last 120 minutes", "env=prod", "projects=core", "deploy_release", "ref=v2026.03.20", "rev=abcdef123456", "link=https://ci.example/run/1"} {
		if !strings.Contains(text, want) {
			t.Fatalf("expected %q in %q", want, text)
		}
	}
}

func TestFormatActiveIncidents(t *testing.T) {
	text := FormatActiveIncidents(IncidentListResponse{
		Count: 1,
		Items: []incident.Record{
			{ID: "ops-scheduler|core|prod", Project: "core", Env: "prod", Status: "fail", Owner: "alice", Summary: "api unhealthy"},
		},
	})
	for _, want := range []string{"active incidents: 1", "project=core", "owner=alice"} {
		if !strings.Contains(text, want) {
			t.Fatalf("expected %q in %q", want, text)
		}
	}
}

func TestFormatIncidentDetail(t *testing.T) {
	text := FormatIncidentDetail(incident.Record{
		ID:             "ops-scheduler|core|prod",
		Project:        "core",
		Env:            "prod",
		Source:         "ops-scheduler",
		Status:         "fail",
		Owner:          "alice",
		Acknowledged:   true,
		AcknowledgedBy: "tg:@ops",
		Summary:        "api unhealthy",
		Highlights:     []string{"service_api [HTTP_DOWN] connection refused"},
		Silence: &incident.ExternalSilence{
			ID:       "sil-123",
			Status:   "active",
			EndsAt:   stringsToTime(t, "2099-03-18T12:00:00Z"),
			StartsAt: stringsToTime(t, "2026-03-18T10:00:00Z"),
		},
		External: &incident.ExternalAlert{
			Provider:  "alertmanager",
			AlertName: "HighErrorRate",
			Labels:    map[string]string{"instance": "api-1:9090"},
		},
	})
	for _, want := range []string{"incident ops-scheduler|core|prod", "owner=alice", "acknowledged_by=tg:@ops", "external=alertmanager", "silence=active id=sil-123"} {
		if !strings.Contains(text, want) {
			t.Fatalf("expected %q in %q", want, text)
		}
	}
}

func TestFormatIncidentDetailWithChanges(t *testing.T) {
	text := FormatIncidentDetailWithChanges(
		incident.Record{
			ID:      "ops-scheduler|core|prod",
			Project: "core",
			Env:     "prod",
			Source:  "ops-scheduler",
			Status:  "fail",
			Summary: "api unhealthy",
		},
		RecentChangesResponse{
			WindowMinutes: 120,
			Count:         1,
			Items: []incident.TimelineEntry{
				{Time: stringsToTime(t, "2026-03-18T10:00:00Z"), Kind: "change", Action: "deploy_release", Status: "ok", Actor: "ci:github-actions", Target: "service/api", Reference: "v2026.03.20", Revision: "abcdef123456", URL: "https://ci.example/run/1"},
			},
		},
	)
	for _, want := range []string{"recent changes last 120 minutes", "deploy_release", "service/api", "ref=v2026.03.20", "rev=abcdef123456"} {
		if !strings.Contains(text, want) {
			t.Fatalf("expected %q in %q", want, text)
		}
	}
}

func TestFormatIncidentTimeline(t *testing.T) {
	text := FormatIncidentTimeline(incident.Timeline{
		Incident:      incident.Record{ID: "ops-scheduler|core|prod", Project: "core", Env: "prod", Status: "fail"},
		WindowMinutes: 90,
		CorrelatedChanges: []incident.TimelineEntry{
			{Time: stringsToTime(t, "2026-03-18T10:00:00Z"), Kind: "change", Action: "restart_container", Status: "ok", Actor: "tg:@ops", TargetHost: "app-1", Reference: "v2026.03.20", Revision: "abcdef123456", URL: "https://ci.example/run/1", LikelyChange: true},
		},
		Entries: []incident.TimelineEntry{
			{Time: stringsToTime(t, "2026-03-18T10:00:00Z"), Kind: "change", Action: "restart_container", Status: "ok", Actor: "tg:@ops", TargetHost: "app-1", Reference: "v2026.03.20", Revision: "abcdef123456", URL: "https://ci.example/run/1", LikelyChange: true},
			{Time: stringsToTime(t, "2026-03-18T10:05:00Z"), Kind: "signal", Action: "health_run", Status: "failed", Message: "HTTP_DOWN: connection refused"},
		},
	})
	for _, want := range []string{"timeline ops-scheduler|core|prod last 90 minutes", "correlated 10:00 change restart_container", "ref=v2026.03.20", "rev=abcdef123456", "events:", "10:05 signal health_run"} {
		if !strings.Contains(text, want) {
			t.Fatalf("expected %q in %q", want, text)
		}
	}
}

func TestFormatActionDetail(t *testing.T) {
	text := FormatActionDetail(approval.Request{
		ID:         "r1",
		Status:     "pending",
		Action:     "restart_container",
		Env:        "prod",
		TargetHost: "app-1",
		Args:       []string{"api-1"},
		Actor:      "tg:@ops",
	})
	for _, want := range []string{"request r1", "status=pending", "target=app-1"} {
		if !strings.Contains(text, want) {
			t.Fatalf("expected %q in %q", want, text)
		}
	}
}

func stringsToTime(t *testing.T, v string) time.Time {
	t.Helper()
	got, err := time.Parse(time.RFC3339, v)
	if err != nil {
		t.Fatal(err)
	}
	return got
}
