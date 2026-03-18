package incident

import (
	"testing"

	"github.com/alan666gg/ops-agent/internal/checks"
	"github.com/alan666gg/ops-agent/internal/config"
	"github.com/alan666gg/ops-agent/internal/policy"
)

func TestBuildSuggestionsForServiceAndHostFailures(t *testing.T) {
	env := config.Environment{
		Hosts: []config.Host{
			{Name: "app-1", Host: "10.0.0.5", SSHUser: "root", SSHPort: 22},
		},
		Services: []config.Service{
			{Name: "api", Type: "container", ContainerName: "api-1", HealthcheckURL: "http://127.0.0.1:8080/healthz"},
		},
		Dependencies: []string{"tcp://127.0.0.1:6379"},
	}
	results := []checks.Result{
		{Name: "host_ssh_app_1", Severity: checks.SeverityFail, Message: "connection refused"},
		{Name: "service_api", Severity: checks.SeverityFail, Message: "status=500"},
		{Name: "dependency_tcp_127_0_0_1_6379", Severity: checks.SeverityWarn, Message: "slow"},
	}
	policyCfg := policy.Config{}
	policyCfg.Policies.AutoActions.Allowed = []string{"check_host_health", "check_service_health", "check_dependencies"}
	policyCfg.Policies.AutoActions.RequireApproval = []string{"restart_container"}

	suggestions := BuildSuggestions("prod", env, results, policyCfg, 0)
	if len(suggestions) != 4 {
		t.Fatalf("expected 4 suggestions, got %d: %#v", len(suggestions), suggestions)
	}

	found := map[string]Suggestion{}
	for _, s := range suggestions {
		found[s.Action+"|"+s.TargetHost] = s
	}
	if got := found["check_host_health|app-1"]; got.TargetHost != "app-1" {
		t.Fatalf("missing host suggestion: %#v", suggestions)
	}
	if got := found["restart_container|"]; len(got.Args) != 1 || got.Args[0] != "api-1" || !got.RequiresApproval {
		t.Fatalf("unexpected restart suggestion: %#v", got)
	}
}

func TestBuildReportSummary(t *testing.T) {
	report := BuildReport("ops-scheduler", "prod", config.Environment{}, []checks.Result{
		{Name: "a", Severity: checks.SeverityPass},
		{Name: "b", Severity: checks.SeverityWarn},
		{Name: "c", Severity: checks.SeverityFail},
	}, policy.Config{}, 0)
	if report.Status != "fail" {
		t.Fatalf("expected fail status, got %s", report.Status)
	}
	if report.FailCount != 1 || report.WarnCount != 1 {
		t.Fatalf("unexpected counts: %+v", report)
	}
}
