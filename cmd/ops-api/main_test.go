package main

import (
	"os"
	"path/filepath"
	"testing"
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
