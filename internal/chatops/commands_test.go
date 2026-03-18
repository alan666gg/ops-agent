package chatops

import (
	"strings"
	"testing"

	"github.com/alan666gg/ops-agent/internal/approval"
	"github.com/alan666gg/ops-agent/internal/checks"
	"github.com/alan666gg/ops-agent/internal/incident"
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
		Results: []checks.Result{
			{Name: "host_ssh_app_1", Code: "TCP_UNREACHABLE", Severity: checks.SeverityFail, Message: "connection refused"},
		},
		SuppressedChecks: []incident.SuppressedCheck{
			{Result: checks.Result{Name: "service_api"}, SuppressedBy: "host_ssh_app_1"},
		},
		Suggestions: []incident.Suggestion{
			{Action: "check_host_health", TargetHost: "app-1"},
		},
	})
	for _, want := range []string{"[FAIL]", "highlight service_runtime_api [CONTAINER_OOMKILLED]", "host_ssh_app_1 [TCP_UNREACHABLE]", "suppressed service_api", "suggest check_host_health"} {
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
