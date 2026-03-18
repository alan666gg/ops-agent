package incident

import (
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/alan666gg/ops-agent/internal/checks"
	"github.com/alan666gg/ops-agent/internal/config"
	"github.com/alan666gg/ops-agent/internal/policy"
)

type Suggestion struct {
	Action           string   `json:"action"`
	Args             []string `json:"args,omitempty"`
	TargetHost       string   `json:"target_host,omitempty"`
	Reason           string   `json:"reason"`
	RequiresApproval bool     `json:"requires_approval"`
}

type Report struct {
	Source        string          `json:"source"`
	Env           string          `json:"env"`
	Status        string          `json:"status"`
	Summary       string          `json:"summary"`
	Fingerprint   string          `json:"fingerprint"`
	TriggeredAt   time.Time       `json:"triggered_at"`
	Results       []checks.Result `json:"results"`
	Suggestions   []Suggestion    `json:"suggestions,omitempty"`
	FailCount     int             `json:"fail_count"`
	WarnCount     int             `json:"warn_count"`
	TotalChecks   int             `json:"total_checks"`
	FailedChecks  []checks.Result `json:"failed_checks,omitempty"`
	WarningChecks []checks.Result `json:"warning_checks,omitempty"`
}

func BuildReport(source, envName string, env config.Environment, results []checks.Result, policyCfg policy.Config, recentAutoActions int) Report {
	report := Report{
		Source:      source,
		Env:         envName,
		Status:      "ok",
		TriggeredAt: time.Now().UTC(),
		Results:     append([]checks.Result(nil), results...),
		TotalChecks: len(results),
	}

	for _, res := range results {
		switch res.Severity {
		case checks.SeverityFail:
			report.FailCount++
			report.FailedChecks = append(report.FailedChecks, res)
			report.Status = "fail"
		case checks.SeverityWarn:
			report.WarnCount++
			report.WarningChecks = append(report.WarningChecks, res)
			if report.Status != "fail" {
				report.Status = "warn"
			}
		}
	}

	report.Suggestions = BuildSuggestions(envName, env, results, policyCfg, recentAutoActions)
	report.Summary = buildSummary(report)
	report.Fingerprint = fingerprint(report)
	return report
}

func BuildSuggestions(envName string, env config.Environment, results []checks.Result, policyCfg policy.Config, recentAutoActions int) []Suggestion {
	var out []Suggestion
	seen := map[string]bool{}
	serviceByKey := map[string]config.Service{}
	hostByKey := map[string]config.Host{}
	depByKey := map[string]string{}

	for _, svc := range env.Services {
		serviceByKey["service_"+sanitizeName(svc.Name)] = svc
	}
	for _, host := range env.Hosts {
		hostByKey["host_ssh_"+sanitizeName(host.Name)] = host
	}
	for _, dep := range env.Dependencies {
		dep = strings.TrimSpace(dep)
		switch {
		case strings.HasPrefix(dep, "tcp://"):
			key := "dependency_tcp_" + sanitizeName(strings.TrimPrefix(dep, "tcp://"))
			depByKey[key] = dep
		case strings.HasPrefix(dep, "http://"), strings.HasPrefix(dep, "https://"):
			key := "dependency_http_" + sanitizeName(depLabel(dep))
			depByKey[key] = dep
		}
	}

	add := func(s Suggestion) {
		key := s.Action + "|" + s.TargetHost + "|" + strings.Join(s.Args, ",")
		if seen[key] {
			return
		}
		seen[key] = true
		decision := policyCfg.Evaluate(s.Action, envName, recentAutoActions)
		s.RequiresApproval = decision.RequiresApproval
		out = append(out, s)
	}

	for _, res := range results {
		if res.Severity == checks.SeverityPass {
			continue
		}
		if host, ok := hostByKey[res.Name]; ok {
			add(Suggestion{
				Action:     "check_host_health",
				TargetHost: host.Name,
				Reason:     fmt.Sprintf("%s: %s", res.Name, res.Message),
			})
			continue
		}
		if svc, ok := serviceByKey[res.Name]; ok {
			if strings.TrimSpace(svc.HealthcheckURL) != "" {
				add(Suggestion{
					Action: "check_service_health",
					Args:   []string{svc.HealthcheckURL},
					Reason: fmt.Sprintf("%s: %s", res.Name, res.Message),
				})
			}
			if res.Severity == checks.SeverityFail && strings.EqualFold(strings.TrimSpace(svc.Type), "container") && strings.TrimSpace(svc.ContainerName) != "" {
				add(Suggestion{
					Action: "restart_container",
					Args:   []string{svc.ContainerName},
					Reason: fmt.Sprintf("%s is container-backed and failing", svc.Name),
				})
			}
			continue
		}
		if dep, ok := depByKey[res.Name]; ok {
			add(Suggestion{
				Action: "check_dependencies",
				Args:   []string{dep},
				Reason: fmt.Sprintf("%s: %s", res.Name, res.Message),
			})
			continue
		}
		if res.Name == "host_basics" {
			add(Suggestion{
				Action: "check_host_health",
				Reason: fmt.Sprintf("%s: %s", res.Name, res.Message),
			})
		}
	}

	return out
}

func buildSummary(report Report) string {
	switch report.Status {
	case "fail":
		return fmt.Sprintf("%s %s: %d failed, %d warning checks out of %d", report.Source, report.Env, report.FailCount, report.WarnCount, report.TotalChecks)
	case "warn":
		return fmt.Sprintf("%s %s: %d warning checks out of %d", report.Source, report.Env, report.WarnCount, report.TotalChecks)
	default:
		return fmt.Sprintf("%s %s: all %d checks passed", report.Source, report.Env, report.TotalChecks)
	}
}

func fingerprint(report Report) string {
	parts := []string{report.Source, report.Env, report.Status}
	for _, res := range report.FailedChecks {
		parts = append(parts, "fail:"+res.Name+":"+res.Code)
	}
	for _, res := range report.WarningChecks {
		parts = append(parts, "warn:"+res.Name+":"+res.Code)
	}
	if len(parts) > 3 {
		sort.Strings(parts[3:])
	}
	sum := sha1.Sum([]byte(strings.Join(parts, "|")))
	return hex.EncodeToString(sum[:])
}

func depLabel(raw string) string {
	trimmed := strings.TrimPrefix(strings.TrimPrefix(raw, "https://"), "http://")
	return trimmed
}

func sanitizeName(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return "unknown"
	}
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z':
			b.WriteRune(r)
		case r >= 'A' && r <= 'Z':
			b.WriteRune(r)
		case r >= '0' && r <= '9':
			b.WriteRune(r)
		default:
			b.WriteByte('_')
		}
	}
	return strings.Trim(b.String(), "_")
}
