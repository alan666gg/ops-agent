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

func TestMemoryStoreAllowsMultipleKeysPerSourceEnv(t *testing.T) {
	store := &MemoryStore{}
	now := time.Now().UTC()
	a, err := store.SyncReport(Report{Source: "alertmanager", Key: "fp-1", Project: "core", Env: "prod", Status: "fail", Summary: "api error rate", Fingerprint: "fp-1", FailCount: 1}, now)
	if err != nil {
		t.Fatal(err)
	}
	b, err := store.SyncReport(Report{Source: "alertmanager", Key: "fp-2", Project: "core", Env: "prod", Status: "warn", Summary: "latency high", Fingerprint: "fp-2", WarnCount: 1}, now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if a.ID == b.ID {
		t.Fatalf("expected distinct incident ids, got %q and %q", a.ID, b.ID)
	}
	items, err := store.List(Filter{Projects: []string{"core"}, OpenOnly: true, Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 2 {
		t.Fatalf("expected two open incidents, got %+v", items)
	}
}

func TestSQLiteStorePersistsExternalAlertContext(t *testing.T) {
	store := SQLiteStore{Path: filepath.Join(t.TempDir(), "incidents.db")}
	now := time.Now().UTC()
	rec, err := store.SyncReport(Report{
		Source:      "alertmanager",
		Key:         "fp-1",
		Project:     "core",
		Env:         "prod",
		Status:      "fail",
		Summary:     "external alert",
		Fingerprint: "fp-1",
		FailCount:   1,
		External: &ExternalAlert{
			Provider:    "alertmanager",
			ExternalURL: "http://alertmanager.test",
			Labels:      map[string]string{"alertname": "HighErrorRate"},
		},
	}, now)
	if err != nil {
		t.Fatal(err)
	}
	rec, err = store.SetSilence(rec.ID, ExternalSilence{
		ID:        "sil-123",
		Status:    "active",
		CreatedBy: "tg:@ops",
		StartsAt:  now,
		EndsAt:    now.Add(2 * time.Hour),
	}, now)
	if err != nil {
		t.Fatal(err)
	}
	got, ok, err := store.Get(rec.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !ok || got.External == nil || got.External.Provider != "alertmanager" || got.External.Labels["alertname"] != "HighErrorRate" {
		t.Fatalf("unexpected external alert context: %+v", got)
	}
	if got.Silence == nil || got.Silence.ID != "sil-123" || !SilenceActive(got.Silence, now.Add(time.Minute)) {
		t.Fatalf("unexpected silence context: %+v", got)
	}
}

func TestMemoryStoreSetAndExpireSilence(t *testing.T) {
	store := &MemoryStore{}
	now := time.Now().UTC()
	rec, err := store.SyncReport(Report{
		Source:      "alertmanager",
		Key:         "fp-1",
		Project:     "core",
		Env:         "prod",
		Status:      "fail",
		Summary:     "external alert",
		Fingerprint: "fp-1",
		FailCount:   1,
		External: &ExternalAlert{
			Provider:    "alertmanager",
			ExternalURL: "http://alertmanager.test",
		},
	}, now)
	if err != nil {
		t.Fatal(err)
	}
	rec, err = store.SetSilence(rec.ID, ExternalSilence{
		ID:        "sil-123",
		Status:    "active",
		CreatedBy: "tg:@ops",
		StartsAt:  now,
		EndsAt:    now.Add(2 * time.Hour),
	}, now)
	if err != nil {
		t.Fatal(err)
	}
	if rec.Silence == nil || rec.Silence.ID != "sil-123" || !SilenceActive(rec.Silence, now.Add(time.Minute)) {
		t.Fatalf("unexpected silence after set: %+v", rec)
	}
	rec, err = store.ExpireSilence(rec.ID, "tg:@ops", "resume notifications", now.Add(10*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if rec.Silence == nil || SilenceActive(rec.Silence, now.Add(11*time.Minute)) || rec.Silence.ExpiredBy != "tg:@ops" {
		t.Fatalf("unexpected silence after expire: %+v", rec)
	}
}

func TestMemoryStoreTracksLifecycleStats(t *testing.T) {
	store := &MemoryStore{}
	now := time.Now().UTC()
	rec, err := store.SyncReport(Report{
		Source:      "ops-scheduler",
		Project:     "core",
		Env:         "prod",
		Status:      "fail",
		Summary:     "api unhealthy",
		Fingerprint: "fp-1",
		FailCount:   1,
	}, now)
	if err != nil {
		t.Fatal(err)
	}
	if rec.OpenCount != 1 || rec.ReopenCount != 0 {
		t.Fatalf("unexpected initial lifecycle counts: %+v", rec)
	}
	rec, err = store.Ack(rec.ID, "tg:@ops", "investigating", now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if rec.AckCount != 1 || rec.TotalAckSeconds < 59 || rec.TotalAckSeconds > 61 {
		t.Fatalf("unexpected ack stats: %+v", rec)
	}
	rec, err = store.SyncReport(Report{
		Source:      "ops-scheduler",
		Project:     "core",
		Env:         "prod",
		Status:      "ok",
		Summary:     "api recovered",
		Fingerprint: "fp-ok",
	}, now.Add(5*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if rec.ResolutionCount != 1 || rec.TotalOpenSeconds < 299 || rec.TotalOpenSeconds > 301 {
		t.Fatalf("unexpected resolution stats: %+v", rec)
	}
	rec, err = store.SyncReport(Report{
		Source:      "ops-scheduler",
		Project:     "core",
		Env:         "prod",
		Status:      "fail",
		Summary:     "api unhealthy again",
		Fingerprint: "fp-2",
		FailCount:   1,
	}, now.Add(10*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if rec.OpenCount != 2 || rec.ReopenCount != 1 || !rec.Open {
		t.Fatalf("unexpected reopen stats: %+v", rec)
	}
	items, err := store.List(Filter{Projects: []string{"core"}})
	if err != nil {
		t.Fatal(err)
	}
	stats := ComputeStats(items, now.Add(11*time.Minute))
	if stats.OpenRecords != 1 || stats.ReopenCount != 1 || stats.AckCount != 1 || stats.ResolutionCount != 1 {
		t.Fatalf("unexpected aggregate stats: %+v", stats)
	}
	if stats.AvgMTTASeconds < 59 || stats.AvgMTTASeconds > 61 || stats.AvgMTTRSeconds < 299 || stats.AvgMTTRSeconds > 301 {
		t.Fatalf("unexpected aggregate timings: %+v", stats)
	}
}
