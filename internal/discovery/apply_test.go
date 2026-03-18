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
			{Name: "api", Host: "app-1", Type: "container", ContainerName: "api", CandidateHealthURLs: []string{"http://10.0.0.5:8080/"}},
			{Name: "worker", Host: "app-1", Type: "container", ContainerName: "worker", CandidateHealthURLs: []string{"http://10.0.0.5:9090/"}},
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
	if len(result.Added) != 1 || result.Added[0].Name != "worker" || result.Added[0].HealthcheckURL != "http://10.0.0.5:9090/" {
		t.Fatalf("unexpected added services: %+v", result.Added)
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
			{Name: "api", Host: "app-1", Type: "container", ContainerName: "api"},
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
