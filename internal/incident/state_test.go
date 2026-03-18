package incident

import (
	"path/filepath"
	"testing"
	"time"
)

func TestMemoryStoreSyncAckAndResetOnFingerprintChange(t *testing.T) {
	store := &MemoryStore{}
	now := time.Now().UTC()
	report := Report{Source: "ops-scheduler", Project: "core", Env: "prod", Status: "fail", Summary: "broken", Fingerprint: "fp1", FailCount: 1}

	rec, err := store.SyncReport(report, now)
	if err != nil {
		t.Fatal(err)
	}
	if !rec.Open || rec.ID == "" {
		t.Fatalf("unexpected open record: %+v", rec)
	}

	rec, err = store.Ack(rec.ID, "tg:@ops", "investigating", now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if !rec.Acknowledged || rec.AcknowledgedBy != "tg:@ops" {
		t.Fatalf("expected acked record, got %+v", rec)
	}

	report.Fingerprint = "fp2"
	report.Summary = "worse"
	rec, err = store.SyncReport(report, now.Add(2*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if rec.Acknowledged {
		t.Fatalf("expected ack to reset on fingerprint change: %+v", rec)
	}
}

func TestSQLiteStoreListOpenAndAssign(t *testing.T) {
	store := SQLiteStore{Path: filepath.Join(t.TempDir(), "incidents.db")}
	now := time.Now().UTC()
	for _, report := range []Report{
		{Source: "ops-scheduler", Project: "core", Env: "prod", Status: "fail", Summary: "core fail", Fingerprint: "fp1", FailCount: 1},
		{Source: "ops-scheduler", Project: "search", Env: "prod", Status: "warn", Summary: "search warn", Fingerprint: "fp2", WarnCount: 1},
	} {
		if _, err := store.SyncReport(report, now); err != nil {
			t.Fatal(err)
		}
	}

	items, err := store.List(Filter{Projects: []string{"core"}, OpenOnly: true, Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 1 || items[0].Project != "core" {
		t.Fatalf("unexpected filtered incidents: %+v", items)
	}

	rec, err := store.Assign(items[0].ID, "alice", "tg:@lead", "taking ownership", now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if rec.Owner != "alice" {
		t.Fatalf("expected owner assignment, got %+v", rec)
	}

	if _, err := store.SyncReport(Report{Source: "ops-scheduler", Project: "core", Env: "prod", Status: "ok", Summary: "recovered", Fingerprint: "ok"}, now.Add(2*time.Minute)); err != nil {
		t.Fatal(err)
	}
	items, err = store.List(Filter{Projects: []string{"core"}, OpenOnly: true, Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 0 {
		t.Fatalf("expected recovered incident to leave open list, got %+v", items)
	}
}
