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

func TestControllerSuppressesDuplicatesAndSendsRecovery(t *testing.T) {
	store := &MemoryStore{}
	rec := &recorder{}
	now := time.Date(2026, 3, 18, 10, 0, 0, 0, time.UTC)
	ctl := NewController(rec, store, "warn", 30*time.Minute, true)
	ctl.Now = func() time.Time { return now }

	fail := incident.Report{Source: "ops-scheduler", Env: "prod", Status: "fail", Fingerprint: "fp1", Summary: "fail"}
	decision, err := ctl.Process(context.Background(), fail)
	if err != nil {
		t.Fatal(err)
	}
	if !decision.Send || decision.Reason != "new incident" {
		t.Fatalf("unexpected first decision: %+v", decision)
	}

	decision, err = ctl.Process(context.Background(), fail)
	if err != nil {
		t.Fatal(err)
	}
	if decision.Send || decision.Reason != "duplicate suppressed" {
		t.Fatalf("unexpected duplicate decision: %+v", decision)
	}

	now = now.Add(5 * time.Minute)
	recovered := incident.Report{Source: "ops-scheduler", Env: "prod", Status: "ok", Fingerprint: "ok", Summary: "recovered"}
	decision, err = ctl.Process(context.Background(), recovered)
	if err != nil {
		t.Fatal(err)
	}
	if !decision.Send || decision.Reason != "recovery" {
		t.Fatalf("unexpected recovery decision: %+v", decision)
	}

	if len(rec.reports) != 2 {
		t.Fatalf("expected 2 notifications, got %d", len(rec.reports))
	}
}

func TestControllerSendsOnChangeAndRepeat(t *testing.T) {
	store := &MemoryStore{}
	rec := &recorder{}
	now := time.Date(2026, 3, 18, 10, 0, 0, 0, time.UTC)
	ctl := NewController(rec, store, "warn", 30*time.Minute, true)
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
