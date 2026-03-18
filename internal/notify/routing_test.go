package notify

import (
	"testing"
	"time"

	"github.com/alan666gg/ops-agent/internal/incident"
)

func TestRouterResolvesRoutesAndSilences(t *testing.T) {
	cfg := RoutingConfig{
		DefaultReceiver: "fallback",
		Receivers: map[string]Receiver{
			"fallback": {Webhook: "https://example.com/fallback"},
			"pager":    {Webhook: "https://example.com/pager"},
		},
		Routes: []Route{
			{
				Name:     "prod-fail",
				Receiver: "pager",
				Match: Matchers{
					Env:      []string{"prod"},
					Severity: []string{"fail"},
				},
			},
		},
		Silences: []Silence{
			{
				Name:     "known-incident",
				StartsAt: "2026-03-18T10:00:00Z",
				EndsAt:   "2026-03-18T11:00:00Z",
				Match: Matchers{
					Env:      []string{"prod"},
					Severity: []string{"fail"},
				},
			},
		},
	}

	resolver, err := cfg.BuildResolver()
	if err != nil {
		t.Fatal(err)
	}

	report := incident.Report{Source: "ops-scheduler", Env: "prod", Status: "fail"}
	delivery := resolver.Resolve(report, time.Date(2026, 3, 18, 10, 30, 0, 0, time.UTC))
	if delivery.Allowed || delivery.Reason != "silenced by known-incident" {
		t.Fatalf("unexpected silenced delivery: %+v", delivery)
	}

	delivery = resolver.Resolve(report, time.Date(2026, 3, 18, 11, 30, 0, 0, time.UTC))
	if !delivery.Allowed || delivery.Notifier == nil || delivery.Reason != "routed by prod-fail to pager" {
		t.Fatalf("unexpected routed delivery: %+v", delivery)
	}

	warn := incident.Report{Source: "ops-scheduler", Env: "test", Status: "warn"}
	delivery = resolver.Resolve(warn, time.Date(2026, 3, 18, 11, 30, 0, 0, time.UTC))
	if !delivery.Allowed || delivery.Reason != "routed to default receiver fallback" {
		t.Fatalf("unexpected default delivery: %+v", delivery)
	}
}

func TestRouterSupportsRecurringMaintenanceWindowAcrossMidnight(t *testing.T) {
	cfg := RoutingConfig{
		DefaultReceiver: "fallback",
		Receivers: map[string]Receiver{
			"fallback": {Webhook: "https://example.com/fallback"},
		},
		MaintenanceWindows: []MaintenanceWindow{
			{
				Name: "nightly-release",
				Match: Matchers{
					Env: []string{"prod"},
				},
				Recurring: &RecurringRange{
					Timezone: "UTC",
					Weekdays: []string{"sat"},
					Start:    "23:00",
					End:      "02:00",
				},
			},
		},
	}

	resolver, err := cfg.BuildResolver()
	if err != nil {
		t.Fatal(err)
	}

	now := time.Date(2026, 3, 22, 0, 30, 0, 0, time.UTC)
	if got := now.Weekday(); got != time.Sunday {
		t.Fatalf("expected sunday fixture, got %s", got)
	}
	report := incident.Report{Source: "ops-scheduler", Env: "prod", Status: "fail"}
	delivery := resolver.Resolve(report, now)
	if delivery.Allowed || delivery.Reason != "suppressed by maintenance window nightly-release" {
		t.Fatalf("unexpected recurring suppression: %+v", delivery)
	}
}

func TestRoutingConfigValidateRejectsMissingReceiverReferences(t *testing.T) {
	cfg := RoutingConfig{
		Receivers: map[string]Receiver{
			"fallback": {Webhook: "https://example.com/fallback"},
		},
		Routes: []Route{
			{Name: "broken", Receiver: "missing"},
		},
	}
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected validation error for missing receiver")
	}
}
