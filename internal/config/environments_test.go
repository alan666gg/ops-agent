package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
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
    prometheus:
      base_url: http://127.0.0.1:9090
      bearer_token_env: PROM_TEST_TOKEN
      timeout: 10s
    hosts:
      - name: app-1
        host: 127.0.0.1
        ssh_user: root
        ssh_port: 22
        checks:
          filesystem_path: /
          required_processes:
            - nginx
    services:
      - name: api
        host: app-1
        type: container
        container_name: app-api
        healthcheck_url: http://127.0.0.1:8080/healthz
        checks:
          restart_warn_count: 2
          restart_fail_count: 5
          restart_flap_window: 15m
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
	prom := cfg.Environments["test"].Prometheus.WithDefaults()
	if prom.BaseURL != "http://127.0.0.1:9090" || prom.BearerTokenEnv != "PROM_TEST_TOKEN" || prom.Timeout != 10*time.Second {
		t.Fatalf("unexpected prometheus config: %+v", prom)
	}
	slo := cfg.Environments["test"].Services[0].SLO.WithDefaults()
	if slo.PageBurnRate != 10 || slo.TicketBurnRate != 2 || slo.MinSamples != 4 {
		t.Fatalf("unexpected slo defaults: %+v", slo)
	}
	hostChecks := cfg.Environments["test"].Hosts[0].Checks.WithDefaults()
	if hostChecks.LoadWarnPerCPU != 1.5 || hostChecks.MemoryFailPercent != 95 || len(hostChecks.RequiredProcesses) != 1 {
		t.Fatalf("unexpected host check defaults: %+v", hostChecks)
	}
	serviceChecks := cfg.Environments["test"].Services[0].Checks.WithDefaults(cfg.Environments["test"].Services[0])
	if serviceChecks.RestartWarnCount != 2 || serviceChecks.RestartFailCount != 5 || serviceChecks.RestartFlapWindow != 15*time.Minute {
		t.Fatalf("unexpected service check config: %+v", serviceChecks)
	}
}

func TestLoadEnvironmentsRejectsInvalidPrometheusConfig(t *testing.T) {
	path := filepath.Join(t.TempDir(), "environments.yaml")
	content := `environments:
  prod:
    prometheus:
      base_url: ftp://127.0.0.1:9090
      bearer_token_env: bad-token
    hosts: []
    services: []
    dependencies: []
`
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	if _, err := LoadEnvironments(path); err == nil {
		t.Fatal("expected invalid prometheus config validation error")
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

func TestLoadEnvironmentsRejectsInvalidHostChecks(t *testing.T) {
	path := filepath.Join(t.TempDir(), "environments.yaml")
	content := `environments:
  prod:
    hosts:
      - name: app-1
        host: 10.0.0.5
        checks:
          load_warn_per_cpu: 3
          load_fail_per_cpu: 2
          filesystem_path: var/log
          required_processes:
            - nginx
            - nginx
    services: []
    dependencies: []
`
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	_, err := LoadEnvironments(path)
	if err == nil {
		t.Fatal("expected invalid host checks validation error")
	}
}

func TestLoadEnvironmentsRejectsInvalidServiceChecks(t *testing.T) {
	path := filepath.Join(t.TempDir(), "environments.yaml")
	content := `environments:
  prod:
    hosts:
      - name: app-1
        host: 10.0.0.5
    services:
      - name: api
        host: app-1
        type: container
        container_name: api
        checks:
          restart_warn_count: 5
          restart_fail_count: 2
      - name: worker
        host: app-1
        type: systemd
        systemd_unit: worker.service
        checks:
          journal_lines: 0
    dependencies: []
`
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	_, err := LoadEnvironments(path)
	if err == nil {
		t.Fatal("expected invalid service checks validation error")
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
						Checks: ServiceChecks{
							RestartWarnCount:  2,
							RestartFailCount:  5,
							RestartFlapWindow: 15 * time.Minute,
						},
					},
					{
						Name:         "nginx",
						Host:         "app-1",
						Type:         "systemd",
						SystemdUnit:  "nginx.service",
						ProcessName:  "nginx",
						ListenerPort: 80,
						Checks: ServiceChecks{
							JournalWindow: 15 * time.Minute,
							JournalLines:  2,
						},
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
	if len(output.Environments["prod"].Services) != 2 || output.Environments["prod"].Services[1].SystemdUnit != "nginx.service" || output.Environments["prod"].Services[0].Checks.RestartWarnCount != 2 {
		t.Fatalf("unexpected output: %+v", output)
	}
}

func TestLoadEnvironmentsAcceptsProjectAndMiddlewareDependencies(t *testing.T) {
	path := filepath.Join(t.TempDir(), "environments.yaml")
	content := `environments:
  prod:
    project: payments
    hosts: []
    services: []
    dependencies:
      - redis://cache.internal:6379/0
      - mysql://db.internal:3306/app
`
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadEnvironments(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := cfg.ProjectForEnv("prod"); got != "payments" {
		t.Fatalf("unexpected project mapping: %q", got)
	}
}

func TestLoadEnvironmentsRejectsInvalidProjectName(t *testing.T) {
	path := filepath.Join(t.TempDir(), "environments.yaml")
	content := `environments:
  prod:
    project: "bad project"
    hosts: []
    services: []
    dependencies: []
`
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadEnvironments(path); err == nil {
		t.Fatal("expected invalid project name error")
	}
}

func TestParseDependencyDefaultsPortsForMiddleware(t *testing.T) {
	scheme, host, port, err := ParseDependency("redis://cache.internal")
	if err != nil {
		t.Fatal(err)
	}
	if scheme != "redis" || host != "cache.internal" || port != "6379" {
		t.Fatalf("unexpected redis dependency parse: %s %s %s", scheme, host, port)
	}
	scheme, host, port, err = ParseDependency("mysql://db.internal/app")
	if err != nil {
		t.Fatal(err)
	}
	if scheme != "mysql" || host != "db.internal" || port != "3306" {
		t.Fatalf("unexpected mysql dependency parse: %s %s %s", scheme, host, port)
	}
}
