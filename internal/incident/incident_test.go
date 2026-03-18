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
			{Name: "api", Host: "app-1", Type: "container", ContainerName: "api-1", HealthcheckURL: "http://10.0.0.5:8080/healthz"},
		},
		Dependencies: []string{"tcp://10.0.0.5:6379"},
	}
	results := []checks.Result{
		{Name: "host_ssh_app_1", Severity: checks.SeverityFail, Message: "connection refused"},
		{Name: "service_api", Severity: checks.SeverityFail, Message: "status=500"},
		{Name: "dependency_tcp_10_0_0_5_6379", Severity: checks.SeverityWarn, Message: "slow"},
	}
	policyCfg := policy.Config{}
	policyCfg.Policies.AutoActions.Allowed = []string{"check_host_health", "check_service_health", "check_dependencies"}
	policyCfg.Policies.AutoActions.RequireApproval = []string{"restart_container"}

	report := BuildReport("ops-scheduler", "prod", env, results, policyCfg, 0)
	suggestions := report.Suggestions
	if len(suggestions) != 1 {
		t.Fatalf("expected 1 root-cause suggestion, got %d: %#v", len(suggestions), suggestions)
	}

	found := map[string]Suggestion{}
	for _, s := range suggestions {
		found[s.Action+"|"+s.TargetHost] = s
	}
	if got := found["check_host_health|app-1"]; got.TargetHost != "app-1" {
		t.Fatalf("missing host suggestion: %#v", suggestions)
	}
	if report.FailCount != 1 || report.WarnCount != 0 || report.SuppressedCount != 2 {
		t.Fatalf("unexpected report counts: %+v", report)
	}
	if len(report.SuppressedChecks) != 2 {
		t.Fatalf("expected suppressed downstream checks, got %+v", report.SuppressedChecks)
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

func TestBuildReportSuppressesDownstreamChecksByHostFailure(t *testing.T) {
	env := config.Environment{
		Hosts: []config.Host{
			{Name: "app-1", Host: "10.0.0.5"},
		},
		Services: []config.Service{
			{Name: "api", Host: "app-1", HealthcheckURL: "http://10.0.0.5:8080/healthz"},
		},
		Dependencies: []string{
			"tcp://10.0.0.5:6379",
			"https://example.com/health",
		},
	}
	results := []checks.Result{
		{Name: "host_ssh_app_1", Code: "TCP_UNREACHABLE", Severity: checks.SeverityFail, Message: "connection refused"},
		{Name: "service_api", Code: "HTTP_DOWN", Severity: checks.SeverityFail, Message: "connection refused"},
		{Name: "dependency_tcp_10_0_0_5_6379", Code: "TCP_UNREACHABLE", Severity: checks.SeverityFail, Message: "connection refused"},
		{Name: "dependency_http_example_com_health", Code: "HTTP_BAD_STATUS", Severity: checks.SeverityWarn, Message: "status=503"},
	}

	report := BuildReport("ops-scheduler", "prod", env, results, policy.Config{}, 0)
	if report.Status != "fail" {
		t.Fatalf("expected root-cause fail status, got %s", report.Status)
	}
	if report.FailCount != 1 || report.WarnCount != 1 || report.SuppressedCount != 2 {
		t.Fatalf("unexpected counts: %+v", report)
	}
	if len(report.FailedChecks) != 1 || report.FailedChecks[0].Name != "host_ssh_app_1" {
		t.Fatalf("unexpected active failures: %+v", report.FailedChecks)
	}
	if len(report.WarningChecks) != 1 || report.WarningChecks[0].Name != "dependency_http_example_com_health" {
		t.Fatalf("unexpected active warnings: %+v", report.WarningChecks)
	}
	if report.Summary == "" || report.Summary == "ops-scheduler prod: 1 failed, 1 warning checks out of 4" {
		t.Fatalf("expected suppression context in summary, got %q", report.Summary)
	}
}
