package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/alan666gg/ops-agent/internal/audit"
	"github.com/alan666gg/ops-agent/internal/incident"
)

func TestResolveAuditFile(t *testing.T) {
	dir := t.TempDir()
	auditDir := filepath.Join(dir, "audit")
	if err := os.MkdirAll(auditDir, 0o755); err != nil {
		t.Fatal(err)
	}
	defaultFile := filepath.Join(auditDir, "api.jsonl")
	if err := os.WriteFile(defaultFile, []byte("{}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(auditDir, "worker.jsonl"), []byte("{}\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	s := &server{auditFile: defaultFile}

	t.Run("default file", func(t *testing.T) {
		got, err := s.resolveAuditFile("")
		if err != nil {
			t.Fatal(err)
		}
		want, err := filepath.EvalSymlinks(defaultFile)
		if err != nil {
			t.Fatal(err)
		}
		if got != want {
			t.Fatalf("expected %s, got %s", want, got)
		}
	})

	t.Run("basename in audit dir", func(t *testing.T) {
		got, err := s.resolveAuditFile("worker.jsonl")
		if err != nil {
			t.Fatal(err)
		}
		want, err := filepath.EvalSymlinks(filepath.Join(auditDir, "worker.jsonl"))
		if err != nil {
			t.Fatal(err)
		}
		if got != want {
			t.Fatalf("unexpected resolved file: %s", got)
		}
	})

	t.Run("reject traversal", func(t *testing.T) {
		if _, err := s.resolveAuditFile("../secrets.txt"); err == nil {
			t.Fatal("expected traversal error")
		}
	})

	t.Run("reject extension", func(t *testing.T) {
		if _, err := s.resolveAuditFile("secrets.txt"); err == nil {
			t.Fatal("expected extension error")
		}
	})
}

func TestResolveTargetHost(t *testing.T) {
	dir := t.TempDir()
	envFile := filepath.Join(dir, "environments.yaml")
	content := `environments:
  prod:
    hosts:
      - name: app-1
        host: 10.0.0.5
        ssh_user: root
        ssh_port: 22
    services: []
    dependencies: []
`
	if err := os.WriteFile(envFile, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	s := &server{envFile: envFile}

	t.Run("empty target host", func(t *testing.T) {
		host, err := s.resolveTargetHost("prod", "")
		if err != nil {
			t.Fatal(err)
		}
		if host != nil {
			t.Fatal("expected nil host")
		}
	})

	t.Run("existing target host", func(t *testing.T) {
		host, err := s.resolveTargetHost("prod", "app-1")
		if err != nil {
			t.Fatal(err)
		}
		if host == nil || host.Host != "10.0.0.5" {
			t.Fatalf("unexpected host: %+v", host)
		}
	})

	t.Run("missing target host", func(t *testing.T) {
		if _, err := s.resolveTargetHost("prod", "missing"); err == nil {
			t.Fatal("expected missing target host error")
		}
	})
}

func TestHandleIncidentTimeline(t *testing.T) {
	now := time.Now().UTC()
	auditFile := filepath.Join(t.TempDir(), "audit.jsonl")
	store := &incident.MemoryStore{}
	record, err := store.SyncReport(incident.Report{
		Source:      "ops-scheduler",
		Project:     "core",
		Env:         "prod",
		Status:      "fail",
		Summary:     "api unhealthy",
		Fingerprint: "fp1",
		FailCount:   1,
	}, now)
	if err != nil {
		t.Fatal(err)
	}
	for _, evt := range []audit.Event{
		{Time: now.Add(-10 * time.Minute), Actor: "tg:@ops", Action: "restart_container", Project: "core", Env: "prod", TargetHost: "app-1", Status: "ok", Message: "manual restart"},
		{Time: now.Add(-5 * time.Minute), Actor: "ops-scheduler", Action: "health_run", Project: "core", Env: "prod", Target: "prod/service_api", Status: "failed", Message: "HTTP_DOWN: connection refused"},
	} {
		if err := audit.AppendJSONL(auditFile, evt); err != nil {
			t.Fatal(err)
		}
	}

	s := &server{
		auditStore:    audit.JSONLStore{Path: auditFile},
		incidentStore: store,
	}
	req := httptest.NewRequest(http.MethodGet, "/incidents/timeline?id="+record.ID+"&minutes=60", nil)
	rr := httptest.NewRecorder()

	s.handleIncidentTimeline(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	var got incident.Timeline
	if err := json.NewDecoder(rr.Body).Decode(&got); err != nil {
		t.Fatal(err)
	}
	if got.Incident.ID != record.ID || got.WindowMinutes != 60 {
		t.Fatalf("unexpected timeline response: %+v", got)
	}
	if len(got.Entries) != 2 {
		t.Fatalf("expected 2 timeline entries, got %+v", got.Entries)
	}
	if len(got.CorrelatedChanges) != 1 || got.CorrelatedChanges[0].Action != "restart_container" {
		t.Fatalf("unexpected correlated changes: %+v", got.CorrelatedChanges)
	}
}
