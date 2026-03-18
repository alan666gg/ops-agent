package incident

import (
	"strings"
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
		{Name: "host_resource_app_1", Severity: checks.SeverityFail, Message: "load/cpu=3.10"},
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
	if report.FailCount != 1 || report.WarnCount != 0 || report.SuppressedCount != 3 {
		t.Fatalf("unexpected report counts: %+v", report)
	}
	if len(report.SuppressedChecks) != 3 {
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
		{Name: "host_resource_app_1", Code: "HOST_RESOURCE_FAIL", Severity: checks.SeverityFail, Message: "load/cpu=3.2"},
		{Name: "host_process_app_1", Code: "HOST_PROCESS_MISSING", Severity: checks.SeverityFail, Message: "missing nginx"},
		{Name: "service_api", Code: "HTTP_DOWN", Severity: checks.SeverityFail, Message: "connection refused"},
		{Name: "dependency_tcp_10_0_0_5_6379", Code: "TCP_UNREACHABLE", Severity: checks.SeverityFail, Message: "connection refused"},
		{Name: "dependency_http_example_com_health", Code: "HTTP_BAD_STATUS", Severity: checks.SeverityWarn, Message: "status=503"},
	}

	report := BuildReport("ops-scheduler", "prod", env, results, policy.Config{}, 0)
	if report.Status != "fail" {
		t.Fatalf("expected root-cause fail status, got %s", report.Status)
	}
	if report.FailCount != 1 || report.WarnCount != 1 || report.SuppressedCount != 4 {
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

func TestBuildSuggestionsForContainerRuntimeFailure(t *testing.T) {
	env := config.Environment{
		Hosts: []config.Host{
			{Name: "app-1", Host: "10.0.0.5"},
		},
		Services: []config.Service{
			{Name: "api", Host: "app-1", Type: "container", ContainerName: "api-1", HealthcheckURL: "http://10.0.0.5:8080/healthz"},
		},
	}
	results := []checks.Result{
		{Name: "service_runtime_api", Code: "CONTAINER_FLAPPING", Severity: checks.SeverityFail, Message: "restart_count=6 exceeds fail threshold=5"},
	}
	policyCfg := policy.Config{}
	policyCfg.Policies.AutoActions.Allowed = []string{"check_service_health"}
	policyCfg.Policies.AutoActions.RequireApproval = []string{"restart_container"}

	report := BuildReport("ops-scheduler", "prod", env, results, policyCfg, 0)
	if len(report.Suggestions) != 2 {
		t.Fatalf("expected 2 suggestions, got %#v", report.Suggestions)
	}
	found := map[string]bool{}
	for _, item := range report.Suggestions {
		found[item.Action] = true
	}
	if !found["check_service_health"] || !found["restart_container"] {
		t.Fatalf("missing expected suggestions: %#v", report.Suggestions)
	}
	if len(report.Highlights) == 0 || !strings.Contains(report.Highlights[0], "service_runtime_api [CONTAINER_FLAPPING]") {
		t.Fatalf("unexpected highlights: %#v", report.Highlights)
	}
}
