package discovery

import (
	"context"
	"testing"
	"time"

	"github.com/alan666gg/ops-agent/internal/config"
)

type fakeProber struct {
	reachable map[string]bool
}

func (p fakeProber) FirstReachable(_ context.Context, urls []string, _ time.Duration) string {
	for _, u := range urls {
		if p.reachable[u] {
			return u
		}
	}
	return ""
}

func TestApplyReportAddsAndUpdatesServices(t *testing.T) {
	env := config.Environment{
		Hosts: []config.Host{{Name: "app-1", Host: "10.0.0.5"}},
		Services: []config.Service{
			{Name: "existing-api", Host: "app-1", Type: "container", ContainerName: "api"},
		},
	}
	report := Report{
		HostName:    "app-1",
		HostAddress: "10.0.0.5",
		SuggestedService: []ServiceCandidate{
			{Name: "api", Host: "app-1", Type: "container", ContainerName: "api", ListenerPort: 8080, CandidateHealthURLs: []string{"http://10.0.0.5:8080/"}},
			{Name: "worker", Host: "app-1", Type: "container", ContainerName: "worker", ListenerPort: 9090, CandidateHealthURLs: []string{"http://10.0.0.5:9090/"}},
		},
	}
	result := ApplyReport(context.Background(), &env, report, ApplyOptions{
		HealthPaths:  []string{"/healthz", "/"},
		ProbeTimeout: time.Second,
		Prober: fakeProber{reachable: map[string]bool{
			"http://10.0.0.5:8080/healthz": true,
			"http://10.0.0.5:9090/":        true,
		}},
	})
	if len(result.Updated) != 1 || result.Updated[0].HealthcheckURL != "http://10.0.0.5:8080/healthz" {
		t.Fatalf("unexpected updated services: %+v", result.Updated)
	}
	if result.Updated[0].ListenerPort != 8080 {
		t.Fatalf("expected listener port to be backfilled, got %+v", result.Updated[0])
	}
	if len(result.Added) != 1 || result.Added[0].Name != "worker" || result.Added[0].HealthcheckURL != "http://10.0.0.5:9090/" {
		t.Fatalf("unexpected added services: %+v", result.Added)
	}
	if result.Added[0].ListenerPort != 9090 {
		t.Fatalf("expected listener port on added service, got %+v", result.Added[0])
	}
	if len(env.Services) != 2 {
		t.Fatalf("unexpected env services: %+v", env.Services)
	}
}

func TestApplyReportGeneratesUniqueServiceNames(t *testing.T) {
	env := config.Environment{
		Services: []config.Service{
			{Name: "api", Host: "app-1", Type: "container", ContainerName: "api-old"},
		},
	}
	report := Report{
		HostName:    "app-1",
		HostAddress: "10.0.0.5",
		SuggestedService: []ServiceCandidate{
			{Name: "api", Host: "app-1", Type: "container", ContainerName: "api", ListenerPort: 8080},
		},
	}
	result := ApplyReport(context.Background(), &env, report, ApplyOptions{
		ProbeTimeout: time.Second,
		Prober:       fakeProber{},
	})
	if len(result.Added) != 1 || result.Added[0].Name != "api-2" {
		t.Fatalf("unexpected added services: %+v", result.Added)
	}
}

func TestApplyReportAddsSystemdAndListenerCandidatesAndSkipsOpaqueOnes(t *testing.T) {
	env := config.Environment{
		Hosts: []config.Host{{Name: "app-1", Host: "10.0.0.5"}},
	}
	report := Report{
		HostName:    "app-1",
		HostAddress: "10.0.0.5",
		SuggestedService: []ServiceCandidate{
			{Name: "nginx", Host: "app-1", Type: "systemd", SystemdUnit: "nginx.service", ProcessName: "nginx", ListenerPort: 80, CandidateHealthURLs: []string{"http://10.0.0.5:80/"}},
			{Name: "custom-app-9090", Host: "app-1", Type: "listener", ProcessName: "custom-app", ListenerPort: 9090, CandidateHealthURLs: []string{"http://10.0.0.5:9090/"}},
			{Name: "worker", Host: "app-1", Type: "container", ContainerName: "worker"},
		},
	}
	result := ApplyReport(context.Background(), &env, report, ApplyOptions{
		HealthPaths:  []string{"/healthz"},
		ProbeTimeout: time.Second,
		Prober:       fakeProber{},
	})
	if len(result.Added) != 2 {
		t.Fatalf("expected 2 added services, got %+v", result.Added)
	}
	if len(result.Skipped) != 1 || result.Skipped[0] != "worker" {
		t.Fatalf("expected worker to be skipped, got %+v", result.Skipped)
	}
	if env.Services[0].ListenerPort == 0 || env.Services[1].ListenerPort == 0 {
		t.Fatalf("expected listener ports to be populated, got %+v", env.Services)
	}
	foundSystemd := false
	foundListener := false
	for _, svc := range env.Services {
		if svc.SystemdUnit == "nginx.service" && svc.Type == "systemd" {
			foundSystemd = true
		}
		if svc.Type == "listener" && svc.ProcessName == "custom-app" && svc.ListenerPort == 9090 {
			foundListener = true
		}
	}
	if !foundSystemd || !foundListener {
		t.Fatalf("unexpected services after apply: %+v", env.Services)
	}
}
