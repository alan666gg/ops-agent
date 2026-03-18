package slo

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/alan666gg/ops-agent/internal/audit"
	"github.com/alan666gg/ops-agent/internal/checks"
	"github.com/alan666gg/ops-agent/internal/config"
)

func TestEvaluateAvailabilityFastBurnFailure(t *testing.T) {
	now := time.Date(2026, 3, 18, 10, 0, 0, 0, time.UTC)
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	env := testEnv()

	events := []audit.Event{
		{Time: now.Add(-1 * time.Minute), Action: "health_cycle", Env: "prod", Target: "prod/service_api", Status: "fail"},
		{Time: now.Add(-10 * time.Minute), Action: "health_cycle", Env: "prod", Target: "prod/service_api", Status: "ok"},
		{Time: now.Add(-20 * time.Minute), Action: "health_cycle", Env: "prod", Target: "prod/service_api", Status: "ok"},
		{Time: now.Add(-30 * time.Minute), Action: "health_cycle", Env: "prod", Target: "prod/service_api", Status: "fail"},
		{Time: now.Add(-40 * time.Minute), Action: "health_cycle", Env: "prod", Target: "prod/service_api", Status: "ok"},
		{Time: now.Add(-50 * time.Minute), Action: "health_cycle", Env: "prod", Target: "prod/service_api", Status: "ok"},
	}
	writeEvents(t, path, events)

	results, err := (Evaluator{Now: func() time.Time { return now }}).EvaluateAvailability(path, "prod", env)
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if results[0].Severity != checks.SeverityFail || results[0].Code != "SLO_BURN_FAST" {
		t.Fatalf("unexpected result: %+v", results[0])
	}
}

func TestEvaluateAvailabilitySlowBurnWarning(t *testing.T) {
	now := time.Date(2026, 3, 18, 10, 0, 0, 0, time.UTC)
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	env := testEnv()

	events := []audit.Event{
		{Time: now.Add(-2 * time.Minute), Action: "health_cycle", Env: "prod", Target: "prod/service_api", Status: "ok"},
		{Time: now.Add(-10 * time.Minute), Action: "health_cycle", Env: "prod", Target: "prod/service_api", Status: "fail"},
		{Time: now.Add(-20 * time.Minute), Action: "health_cycle", Env: "prod", Target: "prod/service_api", Status: "fail"},
		{Time: now.Add(-40 * time.Minute), Action: "health_cycle", Env: "prod", Target: "prod/service_api", Status: "ok"},
		{Time: now.Add(-70 * time.Minute), Action: "health_cycle", Env: "prod", Target: "prod/service_api", Status: "ok"},
		{Time: now.Add(-2 * time.Hour), Action: "health_cycle", Env: "prod", Target: "prod/service_api", Status: "ok"},
		{Time: now.Add(-3 * time.Hour), Action: "health_cycle", Env: "prod", Target: "prod/service_api", Status: "ok"},
		{Time: now.Add(-4 * time.Hour), Action: "health_cycle", Env: "prod", Target: "prod/service_api", Status: "ok"},
	}
	writeEvents(t, path, events)

	results, err := (Evaluator{Now: func() time.Time { return now }}).EvaluateAvailability(path, "prod", env)
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if results[0].Severity != checks.SeverityWarn || results[0].Code != "SLO_BURN_SLOW" {
		t.Fatalf("unexpected result: %+v", results[0])
	}
}

func TestEvaluateAvailabilitySkipsWhenSamplesAreInsufficient(t *testing.T) {
	now := time.Date(2026, 3, 18, 10, 0, 0, 0, time.UTC)
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	env := testEnv()

	writeEvents(t, path, []audit.Event{
		{Time: now.Add(-1 * time.Minute), Action: "health_cycle", Env: "prod", Target: "prod/service_api", Status: "fail"},
		{Time: now.Add(-10 * time.Minute), Action: "health_cycle", Env: "prod", Target: "prod/service_api", Status: "ok"},
	})

	results, err := (Evaluator{Now: func() time.Time { return now }}).EvaluateAvailability(path, "prod", env)
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 0 {
		t.Fatalf("expected no result with insufficient samples, got %+v", results)
	}
}

func writeEvents(t *testing.T, path string, events []audit.Event) {
	t.Helper()
	for _, evt := range events {
		if err := audit.AppendJSONL(path, evt); err != nil {
			t.Fatal(err)
		}
	}
}

func testEnv() config.Environment {
	return config.Environment{
		Services: []config.Service{
			{
				Name:           "api",
				HealthcheckURL: "http://10.0.0.5:8080/healthz",
				SLO: config.ServiceSLO{
					AvailabilityTarget: 99.9,
					PageShortWindow:    5 * time.Minute,
					PageLongWindow:     1 * time.Hour,
					PageBurnRate:       10,
					TicketShortWindow:  30 * time.Minute,
					TicketLongWindow:   6 * time.Hour,
					TicketBurnRate:     2,
					MinSamples:         4,
				},
			},
		},
	}
}
