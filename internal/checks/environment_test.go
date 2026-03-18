package checks

import (
	"context"
	"testing"
	"time"

	"github.com/alan666gg/ops-agent/internal/config"
)

func TestCheckersForEnvironmentIncludesHostsServicesAndDependencies(t *testing.T) {
	env := config.Environment{
		Hosts: []config.Host{
			{Name: "app-1", Host: "10.0.0.5", SSHPort: 2222, Checks: config.HostChecks{RequiredProcesses: []string{"nginx"}}},
			{Name: "app-2", Host: "10.0.0.6"},
		},
		Services: []config.Service{
			{Name: "api", HealthcheckURL: "http://127.0.0.1:8080/healthz"},
			{Name: "redis", Host: "app-1", Type: "systemd", SystemdUnit: "redis-server.service", ListenerPort: 6379},
			{Name: "worker", Host: "app-2", Type: "systemd", SystemdUnit: "worker.service"},
		},
		Dependencies: []string{
			"tcp://127.0.0.1:6379",
			"https://example.com/health",
		},
	}

	items := CheckersForEnvironment(env)
	if len(items) != 11 {
		t.Fatalf("expected 11 checks, got %d", len(items))
	}

	names := make([]string, 0, len(items))
	for _, item := range items {
		names = append(names, item.Name())
	}

	want := map[string]bool{
		"host_basics":                        true,
		"host_ssh_app_1":                     true,
		"host_ssh_app_2":                     true,
		"host_resource_app_1":                true,
		"host_resource_app_2":                true,
		"host_process_app_1":                 true,
		"service_api":                        true,
		"service_redis":                      true,
		"service_worker":                     true,
		"dependency_tcp_127_0_0_1_6379":      true,
		"dependency_http_example_com_health": true,
	}
	for _, name := range names {
		delete(want, name)
	}
	if len(want) != 0 {
		t.Fatalf("missing checks: %#v", want)
	}
}

type gatedChecker struct {
	name    string
	started chan struct{}
	release <-chan struct{}
}

func (c gatedChecker) Name() string { return c.name }

func (c gatedChecker) Run(ctx context.Context) Result {
	close(c.started)
	select {
	case <-ctx.Done():
		return Result{Name: c.name, Code: "CTX_DONE", Message: ctx.Err().Error(), Severity: SeverityFail}
	case <-c.release:
		return Result{Name: c.name, Code: "OK", Message: "done", Severity: SeverityPass}
	}
}

func TestRunAllConcurrentAndStableOrder(t *testing.T) {
	release := make(chan struct{})
	startedA := make(chan struct{})
	startedB := make(chan struct{})

	reg := NewRegistry(
		gatedChecker{name: "a", started: startedA, release: release},
		gatedChecker{name: "b", started: startedB, release: release},
	)

	done := make(chan []Result, 1)
	go func() {
		done <- reg.RunAll(context.Background())
	}()

	waitStarted := func(ch <-chan struct{}, label string) {
		t.Helper()
		select {
		case <-ch:
		case <-time.After(200 * time.Millisecond):
			t.Fatalf("checker %s did not start concurrently", label)
		}
	}
	waitStarted(startedA, "a")
	waitStarted(startedB, "b")

	close(release)

	select {
	case results := <-done:
		if len(results) != 2 {
			t.Fatalf("expected 2 results, got %d", len(results))
		}
		if results[0].Name != "a" || results[1].Name != "b" {
			t.Fatalf("unexpected result order: %#v", results)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("RunAll did not finish")
	}
}
