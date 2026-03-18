package alerting

import (
	"testing"
	"time"
)

func TestAlertmanagerReportsBuildScopedIncidents(t *testing.T) {
	now := time.Date(2026, 3, 18, 15, 0, 0, 0, time.UTC)
	webhook := AlertmanagerWebhook{
		Receiver: "ops-bot",
		CommonLabels: map[string]string{
			"env":      "prod",
			"project":  "core",
			"severity": "critical",
		},
		CommonAnnotations: map[string]string{
			"summary": "API 5xx ratio too high",
		},
		Alerts: []Alert{
			{
				Status:      "firing",
				Fingerprint: "fp-alert-1",
				StartsAt:    now.Add(-5 * time.Minute),
				Labels: map[string]string{
					"alertname": "HighErrorRate",
					"instance":  "api-1:9090",
				},
				Annotations: map[string]string{
					"runbook_url": "https://runbooks.example.com/high-error-rate",
				},
			},
			{
				Status:      "resolved",
				Fingerprint: "fp-alert-2",
				StartsAt:    now.Add(-10 * time.Minute),
				EndsAt:      now.Add(-1 * time.Minute),
				Labels: map[string]string{
					"alertname": "DiskUsageHigh",
					"severity":  "warning",
					"instance":  "api-2:9090",
				},
				Annotations: map[string]string{
					"description": "disk usage recovered",
				},
			},
		},
	}

	reports := webhook.Reports(now, nil)
	if len(reports) != 2 {
		t.Fatalf("expected 2 reports, got %d", len(reports))
	}
	if reports[0].Source != "alertmanager" || reports[0].Key != "fp-alert-1" || reports[0].Project != "core" || reports[0].Env != "prod" {
		t.Fatalf("unexpected first report: %+v", reports[0])
	}
	if reports[0].Status != "fail" || reports[0].FailCount != 1 || len(reports[0].Highlights) < 2 {
		t.Fatalf("unexpected firing report: %+v", reports[0])
	}
	if reports[1].Status != "ok" || reports[1].WarnCount != 0 || reports[1].Fingerprint != "fp-alert-2" {
		t.Fatalf("unexpected resolved report: %+v", reports[1])
	}
}

func TestAlertmanagerReportsResolveProjectFromEnv(t *testing.T) {
	webhook := AlertmanagerWebhook{
		CommonLabels: map[string]string{
			"environment": "payments-prod",
			"severity":    "warning",
		},
		Alerts: []Alert{
			{
				Status: "firing",
				Labels: map[string]string{
					"alertname": "LatencyHigh",
				},
			},
		},
	}

	reports := webhook.Reports(time.Now().UTC(), func(env string) string {
		if env == "payments-prod" {
			return "payments"
		}
		return ""
	})
	if len(reports) != 1 {
		t.Fatalf("expected 1 report, got %d", len(reports))
	}
	if reports[0].Project != "payments" || reports[0].Status != "warn" || reports[0].Key == "" {
		t.Fatalf("unexpected report: %+v", reports[0])
	}
}
