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
        host: app-1
        type: container
        container_name: app-api
        healthcheck_url: http://127.0.0.1:8080/healthz
        slo:
          availability_target: 99.9
          page_short_window: 5m
          page_long_window: 1h
          ticket_short_window: 30m
          ticket_long_window: 6h
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
	slo := cfg.Environments["test"].Services[0].SLO.WithDefaults()
	if slo.PageBurnRate != 10 || slo.TicketBurnRate != 2 || slo.MinSamples != 4 {
		t.Fatalf("unexpected slo defaults: %+v", slo)
	}
}

func TestLoadEnvironmentsRejectsUnknownServiceHost(t *testing.T) {
	path := filepath.Join(t.TempDir(), "environments.yaml")
	content := `environments:
  prod:
    hosts:
      - name: app-1
        host: 10.0.0.5
    services:
      - name: api
        host: missing-host
        healthcheck_url: http://10.0.0.5:8080/healthz
    dependencies: []
`
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	_, err := LoadEnvironments(path)
	if err == nil {
		t.Fatal("expected unknown service host validation error")
	}
}

func TestLoadEnvironmentsRejectsInvalidSLOConfig(t *testing.T) {
	path := filepath.Join(t.TempDir(), "environments.yaml")
	content := `environments:
  prod:
    hosts:
      - name: app-1
        host: 10.0.0.5
    services:
      - name: api
        host: app-1
        healthcheck_url: http://10.0.0.5:8080/healthz
        slo:
          availability_target: 101
    dependencies: []
`
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	_, err := LoadEnvironments(path)
	if err == nil {
		t.Fatal("expected invalid slo validation error")
	}
}

func TestLoadEnvironmentsRejectsIncompleteDiscoveredServiceTypes(t *testing.T) {
	path := filepath.Join(t.TempDir(), "environments.yaml")
	content := `environments:
  prod:
    hosts:
      - name: app-1
        host: 10.0.0.5
    services:
      - name: nginx
        host: app-1
        type: systemd
      - name: admin
        host: app-1
        type: listener
    dependencies: []
`
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	_, err := LoadEnvironments(path)
	if err == nil {
		t.Fatal("expected invalid discovered service type validation error")
	}
}

func TestLoadEnvironmentsAcceptsDiscoveredServiceTypes(t *testing.T) {
	path := filepath.Join(t.TempDir(), "environments.yaml")
	content := `environments:
  prod:
    hosts:
      - name: app-1
        host: 10.0.0.5
    services:
      - name: nginx
        host: app-1
        type: systemd
        systemd_unit: nginx.service
        process_name: nginx
        listener_port: 80
      - name: admin
        host: app-1
        type: listener
        process_name: custom-app
        listener_port: 9090
    dependencies: []
`
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	cfg, err := LoadEnvironments(path)
	if err != nil {
		t.Fatalf("expected valid discovered service config, got %v", err)
	}
	if got := cfg.Environments["prod"].Services; len(got) != 2 || got[0].SystemdUnit == "" || got[1].ListenerPort != 9090 {
		t.Fatalf("unexpected services: %+v", got)
	}
}

func TestLoadEnvironmentsRejectsDuplicateSystemdAndListenerTargets(t *testing.T) {
	path := filepath.Join(t.TempDir(), "environments.yaml")
	content := `environments:
  prod:
    hosts:
      - name: app-1
        host: 10.0.0.5
    services:
      - name: nginx
        host: app-1
        type: systemd
        systemd_unit: nginx.service
      - name: nginx-copy
        host: app-1
        type: systemd
        systemd_unit: nginx.service
      - name: admin
        host: app-1
        type: listener
        listener_port: 9090
      - name: admin-copy
        host: app-1
        type: listener
        listener_port: 9090
    dependencies: []
`
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	_, err := LoadEnvironments(path)
	if err == nil {
		t.Fatal("expected duplicate discovered target validation error")
	}
}

func TestSaveEnvironmentsRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "environments.yaml")
	input := EnvironmentFile{
		Environments: map[string]Environment{
			"prod": {
				Hosts: []Host{{Name: "app-1", Host: "10.0.0.5", SSHUser: "root", SSHPort: 22}},
				Services: []Service{
					{
						Name:           "api",
						Host:           "app-1",
						Type:           "container",
						ContainerName:  "api",
						ListenerPort:   8080,
						HealthcheckURL: "http://10.0.0.5:8080/healthz",
					},
					{
						Name:         "nginx",
						Host:         "app-1",
						Type:         "systemd",
						SystemdUnit:  "nginx.service",
						ProcessName:  "nginx",
						ListenerPort: 80,
					},
				},
			},
		},
	}
	if err := SaveEnvironments(path, input); err != nil {
		t.Fatal(err)
	}
	output, err := LoadEnvironments(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(output.Environments["prod"].Services) != 2 || output.Environments["prod"].Services[1].SystemdUnit != "nginx.service" {
		t.Fatalf("unexpected output: %+v", output)
	}
}
