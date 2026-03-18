package checks

import (
	"context"
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
		Runner: fakeScriptRunner{output: `{"restart_count":1,"state":{"status":"running","running":true,"restarting":false,"error":"","started_at":"` + time.Now().UTC().Add(-5*time.Minute).Format(time.RFC3339Nano) + `"}}`},
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
		Runner: fakeScriptRunner{output: `{"restart_count":6,"state":{"status":"running","running":true,"restarting":false,"error":"","started_at":"2026-03-18T10:00:00Z"}}`},
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
		Runner: fakeScriptRunner{output: "panic: database unavailable\nretry loop exceeded\n"},
	}

	result := checker.Run(context.Background())
	if result.Severity != SeverityWarn || result.Code != "SYSTEMD_RECENT_ERRORS" {
		t.Fatalf("unexpected result: %+v", result)
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
