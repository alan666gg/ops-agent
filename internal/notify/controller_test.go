package notify

import (
	"context"
	"testing"
	"time"

	"github.com/alan666gg/ops-agent/internal/incident"
)

type recorder struct {
	reports []incident.Report
}

func (r *recorder) Notify(_ context.Context, report incident.Report) error {
	r.reports = append(r.reports, report)
	return nil
}

type resolverFunc func(report incident.Report, now time.Time) Delivery

func (f resolverFunc) Resolve(report incident.Report, now time.Time) Delivery {
	return f(report, now)
}

func TestControllerSuppressesDuplicatesAndSendsRecovery(t *testing.T) {
	store := &MemoryStore{}
	rec := &recorder{}
	now := time.Date(2026, 3, 18, 10, 0, 0, 0, time.UTC)
	ctl := NewController(rec, store, ControllerOptions{
		MinSeverity:    "warn",
		RepeatInterval: 30 * time.Minute,
		NotifyRecovery: true,
		TriggerAfter:   2,
		RecoveryAfter:  2,
	})
	ctl.Now = func() time.Time { return now }

	fail := incident.Report{Source: "ops-scheduler", Env: "prod", Status: "fail", Fingerprint: "fp1", Summary: "fail"}
	decision, err := ctl.Process(context.Background(), fail)
	if err != nil {
		t.Fatal(err)
	}
	if decision.Send || decision.Reason != "awaiting trigger threshold (1/2)" {
		t.Fatalf("unexpected first decision: %+v", decision)
	}

	decision, err = ctl.Process(context.Background(), fail)
	if err != nil {
		t.Fatal(err)
	}
	if !decision.Send || decision.Reason != "trigger threshold reached" {
		t.Fatalf("unexpected second decision: %+v", decision)
	}

	now = now.Add(5 * time.Minute)
	recovered := incident.Report{Source: "ops-scheduler", Env: "prod", Status: "ok", Fingerprint: "ok", Summary: "recovered"}
	decision, err = ctl.Process(context.Background(), recovered)
	if err != nil {
		t.Fatal(err)
	}
	if decision.Send || decision.Reason != "awaiting recovery confirmation (1/2)" {
		t.Fatalf("unexpected first recovery decision: %+v", decision)
	}

	now = now.Add(5 * time.Minute)
	decision, err = ctl.Process(context.Background(), recovered)
	if err != nil {
		t.Fatal(err)
	}
	if !decision.Send || decision.Reason != "recovery" {
		t.Fatalf("unexpected confirmed recovery decision: %+v", decision)
	}

	if len(rec.reports) != 2 {
		t.Fatalf("expected 2 notifications, got %d", len(rec.reports))
	}
}

func TestControllerSendsOnChangeAndRepeat(t *testing.T) {
	store := &MemoryStore{}
	rec := &recorder{}
	now := time.Date(2026, 3, 18, 10, 0, 0, 0, time.UTC)
	ctl := NewController(rec, store, ControllerOptions{
		MinSeverity:    "warn",
		RepeatInterval: 30 * time.Minute,
		NotifyRecovery: true,
		TriggerAfter:   1,
		RecoveryAfter:  1,
	})
	ctl.Now = func() time.Time { return now }

	warn := incident.Report{Source: "ops-api", Env: "prod", Status: "warn", Fingerprint: "fp1", Summary: "warn"}
	decision, err := ctl.Process(context.Background(), warn)
	if err != nil {
		t.Fatal(err)
	}
	if !decision.Send {
		t.Fatalf("expected first warn to send: %+v", decision)
	}

	now = now.Add(10 * time.Minute)
	changed := incident.Report{Source: "ops-api", Env: "prod", Status: "warn", Fingerprint: "fp2", Summary: "changed"}
	decision, err = ctl.Process(context.Background(), changed)
	if err != nil {
		t.Fatal(err)
	}
	if !decision.Send || decision.Reason != "incident changed" {
		t.Fatalf("unexpected changed decision: %+v", decision)
	}

	now = now.Add(31 * time.Minute)
	decision, err = ctl.Process(context.Background(), changed)
	if err != nil {
		t.Fatal(err)
	}
	if !decision.Send || decision.Reason != "repeat interval reached" {
		t.Fatalf("unexpected repeat decision: %+v", decision)
	}
}

func TestControllerResetsFailureThresholdOnFlapping(t *testing.T) {
	store := &MemoryStore{}
	rec := &recorder{}
	now := time.Date(2026, 3, 18, 10, 0, 0, 0, time.UTC)
	ctl := NewController(rec, store, ControllerOptions{
		MinSeverity:    "warn",
		RepeatInterval: 30 * time.Minute,
		NotifyRecovery: true,
		TriggerAfter:   2,
		RecoveryAfter:  2,
	})
	ctl.Now = func() time.Time { return now }

	fail := incident.Report{Source: "ops-scheduler", Env: "prod", Status: "fail", Fingerprint: "fp1", Summary: "fail"}
	ok := incident.Report{Source: "ops-scheduler", Env: "prod", Status: "ok", Fingerprint: "ok", Summary: "ok"}

	decision, err := ctl.Process(context.Background(), fail)
	if err != nil {
		t.Fatal(err)
	}
	if decision.Send {
		t.Fatalf("expected first fail to be suppressed: %+v", decision)
	}

	now = now.Add(1 * time.Minute)
	decision, err = ctl.Process(context.Background(), ok)
	if err != nil {
		t.Fatal(err)
	}
	if decision.Send || decision.Reason != "below threshold" {
		t.Fatalf("unexpected recovery-before-open decision: %+v", decision)
	}

	now = now.Add(1 * time.Minute)
	decision, err = ctl.Process(context.Background(), fail)
	if err != nil {
		t.Fatal(err)
	}
	if decision.Send || decision.Reason != "awaiting trigger threshold (1/2)" {
		t.Fatalf("unexpected second fail decision: %+v", decision)
	}

	now = now.Add(1 * time.Minute)
	decision, err = ctl.Process(context.Background(), fail)
	if err != nil {
		t.Fatal(err)
	}
	if !decision.Send || decision.Reason != "trigger threshold reached" {
		t.Fatalf("expected threshold to trigger after consecutive failures: %+v", decision)
	}
}

func TestControllerClosesWithoutRecoveryNotificationWhenDisabled(t *testing.T) {
	store := &MemoryStore{}
	rec := &recorder{}
	now := time.Date(2026, 3, 18, 10, 0, 0, 0, time.UTC)
	ctl := NewController(rec, store, ControllerOptions{
		MinSeverity:    "warn",
		RepeatInterval: 30 * time.Minute,
		NotifyRecovery: false,
		TriggerAfter:   1,
		RecoveryAfter:  2,
	})
	ctl.Now = func() time.Time { return now }

	fail := incident.Report{Source: "ops-api", Env: "prod", Status: "warn", Fingerprint: "fp1", Summary: "warn"}
	decision, err := ctl.Process(context.Background(), fail)
	if err != nil {
		t.Fatal(err)
	}
	if !decision.Send || decision.Reason != "new incident" {
		t.Fatalf("unexpected open decision: %+v", decision)
	}

	now = now.Add(1 * time.Minute)
	ok := incident.Report{Source: "ops-api", Env: "prod", Status: "ok", Fingerprint: "ok", Summary: "ok"}
	decision, err = ctl.Process(context.Background(), ok)
	if err != nil {
		t.Fatal(err)
	}
	if decision.Send || decision.Reason != "awaiting recovery confirmation (1/2)" {
		t.Fatalf("unexpected first recovery decision: %+v", decision)
	}

	now = now.Add(1 * time.Minute)
	decision, err = ctl.Process(context.Background(), ok)
	if err != nil {
		t.Fatal(err)
	}
	if decision.Send || decision.Reason != "recovery suppressed" {
		t.Fatalf("unexpected final recovery decision: %+v", decision)
	}

	if len(rec.reports) != 1 {
		t.Fatalf("expected only the incident opening to notify, got %d", len(rec.reports))
	}
}

func TestControllerDeliversAfterMaintenanceWindowEnds(t *testing.T) {
	store := &MemoryStore{}
	rec := &recorder{}
	now := time.Date(2026, 3, 18, 10, 0, 0, 0, time.UTC)
	cutover := now.Add(5 * time.Minute)
	ctl := NewController(nil, store, ControllerOptions{
		MinSeverity:    "warn",
		RepeatInterval: 30 * time.Minute,
		NotifyRecovery: true,
		TriggerAfter:   1,
		RecoveryAfter:  1,
		Resolver: resolverFunc(func(_ incident.Report, ts time.Time) Delivery {
			if ts.Before(cutover) {
				return Delivery{Allowed: false, Reason: "suppressed by maintenance window prod-release"}
			}
			return Delivery{Allowed: true, Reason: "routed to ops", Notifier: rec}
		}),
	})
	ctl.Now = func() time.Time { return now }

	fail := incident.Report{Source: "ops-scheduler", Env: "prod", Status: "fail", Fingerprint: "fp1", Summary: "fail"}
	decision, err := ctl.Process(context.Background(), fail)
	if err != nil {
		t.Fatal(err)
	}
	if decision.Send || decision.Reason != "new incident; suppressed by maintenance window prod-release" {
		t.Fatalf("unexpected suppressed decision: %+v", decision)
	}

	now = cutover
	decision, err = ctl.Process(context.Background(), fail)
	if err != nil {
		t.Fatal(err)
	}
	if !decision.Send || decision.Reason != "pending first delivery; routed to ops" {
		t.Fatalf("unexpected delayed delivery decision: %+v", decision)
	}
	if len(rec.reports) != 1 {
		t.Fatalf("expected one delayed notification, got %d", len(rec.reports))
	}
}

func TestControllerDropsRecoveryIfIncidentWasNeverDelivered(t *testing.T) {
	store := &MemoryStore{}
	now := time.Date(2026, 3, 18, 10, 0, 0, 0, time.UTC)
	ctl := NewController(nil, store, ControllerOptions{
		MinSeverity:    "warn",
		RepeatInterval: 30 * time.Minute,
		NotifyRecovery: true,
		TriggerAfter:   1,
		RecoveryAfter:  1,
		Resolver: resolverFunc(func(_ incident.Report, _ time.Time) Delivery {
			return Delivery{Allowed: false, Reason: "silenced by known-incident"}
		}),
	})
	ctl.Now = func() time.Time { return now }

	fail := incident.Report{Source: "ops-scheduler", Env: "prod", Status: "fail", Fingerprint: "fp1", Summary: "fail"}
	decision, err := ctl.Process(context.Background(), fail)
	if err != nil {
		t.Fatal(err)
	}
	if decision.Send {
		t.Fatalf("expected failure to be suppressed: %+v", decision)
	}

	now = now.Add(2 * time.Minute)
	ok := incident.Report{Source: "ops-scheduler", Env: "prod", Status: "ok", Fingerprint: "ok", Summary: "ok"}
	decision, err = ctl.Process(context.Background(), ok)
	if err != nil {
		t.Fatal(err)
	}
	if decision.Send || decision.Reason != "recovered before notification" {
		t.Fatalf("unexpected recovery decision: %+v", decision)
	}
}
