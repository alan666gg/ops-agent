package checks

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/alan666gg/ops-agent/internal/config"
)

func TestContainerRuntimeCheckerWarnsOnRecentRestart(t *testing.T) {
	checker := ContainerRuntimeChecker{
		NameLabel:     "service_runtime_api",
		Host:          config.Host{Name: "app-1", Host: "10.0.0.5"},
		ContainerName: "api",
		Checks: config.ServiceChecks{
			RestartWarnCount:  2,
			RestartFailCount:  5,
			RestartFlapWindow: 15 * time.Minute,
		},
		Runner: fakeScriptRunner{output: `{"restart_count":1,"state":{"status":"running","running":true,"restarting":false,"oom_killed":false,"error":"","exit_code":0,"started_at":"` + time.Now().UTC().Add(-5*time.Minute).Format(time.RFC3339Nano) + `","finished_at":"0001-01-01T00:00:00Z"}}`},
	}

	result := checker.Run(context.Background())
	if result.Severity != SeverityWarn || result.Code != "CONTAINER_RECENT_RESTART" {
		t.Fatalf("unexpected result: %+v", result)
	}
}

func TestContainerRuntimeCheckerFailsOnFlapping(t *testing.T) {
	checker := ContainerRuntimeChecker{
		NameLabel:     "service_runtime_api",
		Host:          config.Host{Name: "app-1", Host: "10.0.0.5"},
		ContainerName: "api",
		Checks: config.ServiceChecks{
			RestartWarnCount: 2,
			RestartFailCount: 4,
		},
		Runner: fakeScriptRunner{output: `{"restart_count":6,"state":{"status":"running","running":true,"restarting":false,"oom_killed":false,"error":"","exit_code":0,"started_at":"2026-03-18T10:00:00Z","finished_at":"0001-01-01T00:00:00Z"}}`},
	}

	result := checker.Run(context.Background())
	if result.Severity != SeverityFail || result.Code != "CONTAINER_FLAPPING" {
		t.Fatalf("unexpected result: %+v", result)
	}
}

func TestSystemdJournalCheckerWarnsOnRecentErrors(t *testing.T) {
	checker := SystemdJournalChecker{
		NameLabel: "service_logs_worker",
		Host:      config.Host{Name: "app-1", Host: "10.0.0.5"},
		Unit:      "worker.service",
		Checks: config.ServiceChecks{
			JournalWindow: 15 * time.Minute,
			JournalLines:  2,
		},
		Runner: fakeScriptRunner{output: "panic: database unavailable\npanic: database unavailable\nretry loop exceeded\n"},
	}

	result := checker.Run(context.Background())
	if result.Severity != SeverityWarn || result.Code != "SYSTEMD_RECENT_ERRORS" {
		t.Fatalf("unexpected result: %+v", result)
	}
	if !strings.Contains(result.Message, "[2x] panic: database unavailable") {
		t.Fatalf("expected deduped log summary, got %s", result.Message)
	}
}

func TestSystemdJournalCheckerPassesWithoutErrors(t *testing.T) {
	checker := SystemdJournalChecker{
		NameLabel: "service_logs_worker",
		Host:      config.Host{Name: "app-1", Host: "10.0.0.5"},
		Unit:      "worker.service",
		Runner:    fakeScriptRunner{output: "\n"},
	}

	result := checker.Run(context.Background())
	if result.Severity != SeverityPass || result.Code != "OK" {
		t.Fatalf("unexpected result: %+v", result)
	}
}

func TestContainerRuntimeCheckerWarnsOnRecoveredOOMKill(t *testing.T) {
	checker := ContainerRuntimeChecker{
		NameLabel:     "service_runtime_api",
		Host:          config.Host{Name: "app-1", Host: "10.0.0.5"},
		ContainerName: "api",
		Runner:        fakeScriptRunner{output: `{"restart_count":1,"state":{"status":"running","running":true,"restarting":false,"oom_killed":true,"error":"","exit_code":137,"started_at":"2026-03-18T10:00:00Z","finished_at":"2026-03-18T09:58:00Z"}}`},
	}

	result := checker.Run(context.Background())
	if result.Severity != SeverityWarn || result.Code != "CONTAINER_OOMKILLED" {
		t.Fatalf("unexpected result: %+v", result)
	}
}

func TestContainerRuntimeCheckerFailsOnExitedNonZero(t *testing.T) {
	checker := ContainerRuntimeChecker{
		NameLabel:     "service_runtime_api",
		Host:          config.Host{Name: "app-1", Host: "10.0.0.5"},
		ContainerName: "api",
		Runner:        fakeScriptRunner{output: `{"restart_count":0,"state":{"status":"exited","running":false,"restarting":false,"oom_killed":false,"error":"panic","exit_code":2,"started_at":"2026-03-18T09:00:00Z","finished_at":"2026-03-18T09:01:00Z"}}`},
	}

	result := checker.Run(context.Background())
	if result.Severity != SeverityFail || result.Code != "CONTAINER_EXITED_NONZERO" {
		t.Fatalf("unexpected result: %+v", result)
	}
}

func TestSummarizeLogLinesDedupesAndTrims(t *testing.T) {
	got := summarizeLogLines([]string{
		"panic: database unavailable",
		"panic: database unavailable",
		"retry loop exceeded due to upstream timeout while flushing queue",
		"second unique error",
	}, 2)
	if !strings.Contains(got, "[2x] panic: database unavailable") || !strings.Contains(got, "... and 1 more unique errors") {
		t.Fatalf("unexpected summary: %s", got)
	}
}
