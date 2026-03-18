package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadEnvironmentsValidatesDuplicates(t *testing.T) {
	path := filepath.Join(t.TempDir(), "environments.yaml")
	content := `environments:
  prod:
    hosts:
      - name: app-1
        host: 10.0.0.1
      - name: app-1
        host: 10.0.0.2
`
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	_, err := LoadEnvironments(path)
	if err == nil {
		t.Fatal("expected duplicate host validation error")
	}
}

func TestLoadEnvironmentsValidatesDependencyFormat(t *testing.T) {
	path := filepath.Join(t.TempDir(), "environments.yaml")
	content := `environments:
  prod:
    hosts: []
    services: []
    dependencies:
      - tcp://10.0.0.1
`
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	_, err := LoadEnvironments(path)
	if err == nil {
		t.Fatal("expected dependency validation error")
	}
}

func TestLoadEnvironmentsAcceptsValidConfig(t *testing.T) {
	path := filepath.Join(t.TempDir(), "environments.yaml")
	content := `environments:
  test:
    hosts:
      - name: app-1
        host: 127.0.0.1
        ssh_user: root
        ssh_port: 22
    services:
      - name: api
        type: container
        container_name: app-api
        healthcheck_url: http://127.0.0.1:8080/healthz
    dependencies:
      - tcp://127.0.0.1:6379
      - https://example.com/health
`
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	cfg, err := LoadEnvironments(path)
	if err != nil {
		t.Fatalf("expected valid config, got %v", err)
	}
	if len(cfg.Environments) != 1 {
		t.Fatalf("expected 1 environment, got %d", len(cfg.Environments))
	}
}
