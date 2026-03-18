package incident

import (
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"net"
	"net/url"
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

type SuppressedCheck struct {
	Result       checks.Result `json:"result"`
	SuppressedBy string        `json:"suppressed_by"`
	Reason       string        `json:"reason"`
}

type Report struct {
	Source           string            `json:"source"`
	Key              string            `json:"key,omitempty"`
	Project          string            `json:"project,omitempty"`
	Env              string            `json:"env"`
	Status           string            `json:"status"`
	Summary          string            `json:"summary"`
	Highlights       []string          `json:"highlights,omitempty"`
	Fingerprint      string            `json:"fingerprint"`
	TriggeredAt      time.Time         `json:"triggered_at"`
	Results          []checks.Result   `json:"results"`
	Suggestions      []Suggestion      `json:"suggestions,omitempty"`
	FailCount        int               `json:"fail_count"`
	WarnCount        int               `json:"warn_count"`
	SuppressedCount  int               `json:"suppressed_count"`
	TotalChecks      int               `json:"total_checks"`
	FailedChecks     []checks.Result   `json:"failed_checks,omitempty"`
	WarningChecks    []checks.Result   `json:"warning_checks,omitempty"`
	SuppressedChecks []SuppressedCheck `json:"suppressed_checks,omitempty"`
}

func BuildReport(source, envName string, env config.Environment, results []checks.Result, policyCfg policy.Config, recentAutoActions int) Report {
	report := Report{
		Source:      source,
		Project:     env.ProjectName(),
		Env:         envName,
		Status:      "ok",
		TriggeredAt: time.Now().UTC(),
		Results:     append([]checks.Result(nil), results...),
		TotalChecks: len(results),
	}
	suppressions := BuildSuppressions(env, results)
	var actionable []checks.Result

	for _, res := range results {
		if sup, ok := suppressions[res.Name]; ok && res.Severity != checks.SeverityPass {
			report.SuppressedCount++
			report.SuppressedChecks = append(report.SuppressedChecks, SuppressedCheck{
				Result:       res,
				SuppressedBy: sup.SuppressedBy,
				Reason:       sup.Reason,
			})
			continue
		}
		switch res.Severity {
		case checks.SeverityFail:
			actionable = append(actionable, res)
			report.FailCount++
			report.FailedChecks = append(report.FailedChecks, res)
			report.Status = "fail"
		case checks.SeverityWarn:
			actionable = append(actionable, res)
			report.WarnCount++
			report.WarningChecks = append(report.WarningChecks, res)
			if report.Status != "fail" {
				report.Status = "warn"
			}
		}
	}

	report.Suggestions = BuildSuggestions(envName, env, actionable, policyCfg, recentAutoActions)
	report.Summary = buildSummary(report)
	report.Highlights = buildHighlights(report)
	report.Fingerprint = fingerprint(report)
	return report
}

type suppression struct {
	SuppressedBy string
	Reason       string
}

func BuildSuppressions(env config.Environment, results []checks.Result) map[string]suppression {
	hostFailures := failingHosts(env, results)
	if len(hostFailures) == 0 {
		return nil
	}
	out := map[string]suppression{}

	for _, svc := range env.Services {
		host, ok := serviceHost(env, svc)
		if !ok {
			continue
		}
		root, ok := hostFailures[host.Name]
		if !ok {
			continue
		}
		out["service_"+sanitizeName(svc.Name)] = suppression{
			SuppressedBy: root.SuppressedBy,
			Reason:       fmt.Sprintf("service depends on host %s reachability", host.Name),
		}
		out["service_runtime_"+sanitizeName(svc.Name)] = suppression{
			SuppressedBy: root.SuppressedBy,
			Reason:       fmt.Sprintf("service runtime checks depend on host %s reachability", host.Name),
		}
		out["service_logs_"+sanitizeName(svc.Name)] = suppression{
			SuppressedBy: root.SuppressedBy,
			Reason:       fmt.Sprintf("service log checks depend on host %s reachability", host.Name),
		}
	}

	for _, host := range env.Hosts {
		root, ok := hostFailures[host.Name]
		if !ok {
			continue
		}
		out["host_resource_"+sanitizeName(host.Name)] = suppression{
			SuppressedBy: root.SuppressedBy,
			Reason:       fmt.Sprintf("resource checks require host %s ssh reachability", host.Name),
		}
		out["host_process_"+sanitizeName(host.Name)] = suppression{
			SuppressedBy: root.SuppressedBy,
			Reason:       fmt.Sprintf("process checks require host %s ssh reachability", host.Name),
		}
	}

	for key, hostName := range dependencyHosts(env) {
		root, ok := hostFailures[hostName]
		if !ok {
			continue
		}
		out[key] = suppression{
			SuppressedBy: root.SuppressedBy,
			Reason:       fmt.Sprintf("dependency endpoint is hosted on %s", hostName),
		}
	}
	return out
}

func BuildSuggestions(envName string, env config.Environment, results []checks.Result, policyCfg policy.Config, recentAutoActions int) []Suggestion {
	var out []Suggestion
	seen := map[string]bool{}
	serviceByKey := map[string]config.Service{}
	hostByKey := map[string]config.Host{}
	depByKey := map[string]string{}

	for _, svc := range env.Services {
		suffix := sanitizeName(svc.Name)
		serviceByKey["service_"+suffix] = svc
		serviceByKey["service_runtime_"+suffix] = svc
		serviceByKey["service_logs_"+suffix] = svc
	}
	for _, host := range env.Hosts {
		suffix := sanitizeName(host.Name)
		hostByKey["host_ssh_"+suffix] = host
		hostByKey["host_resource_"+suffix] = host
		hostByKey["host_process_"+suffix] = host
	}
	for _, dep := range env.Dependencies {
		dep = strings.TrimSpace(dep)
		scheme, host, port, err := config.ParseDependency(dep)
		if err != nil {
			continue
		}
		switch scheme {
		case "tcp":
			depByKey["dependency_tcp_"+sanitizeName(net.JoinHostPort(host, port))] = dep
		case "http", "https":
			depByKey["dependency_http_"+sanitizeName(depLabel(dep))] = dep
		case "redis":
			depByKey["dependency_redis_"+sanitizeName(net.JoinHostPort(host, port))] = dep
		case "mysql":
			depByKey["dependency_mysql_"+sanitizeName(net.JoinHostPort(host, port))] = dep
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
			host, hasHost := serviceHost(env, svc)
			if strings.TrimSpace(svc.HealthcheckURL) != "" {
				add(Suggestion{
					Action: "check_service_health",
					Args:   []string{svc.HealthcheckURL},
					Reason: fmt.Sprintf("%s: %s", res.Name, res.Message),
				})
			}
			if hasHost && strings.EqualFold(strings.TrimSpace(svc.Type), "container") {
				switch res.Code {
				case "CONTAINER_OOMKILLED", "CONTAINER_FLAPPING":
					add(Suggestion{
						Action:     "check_host_health",
						TargetHost: host.Name,
						Reason:     fmt.Sprintf("%s on %s needs host-level inspection before restart (%s)", svc.Name, host.Name, res.Code),
					})
					continue
				}
			}
			if hasHost && strings.EqualFold(strings.TrimSpace(svc.Type), "systemd") && strings.HasPrefix(res.Name, "service_logs_") {
				add(Suggestion{
					Action:     "check_host_health",
					TargetHost: host.Name,
					Reason:     fmt.Sprintf("%s reported recent systemd errors on %s", svc.Name, host.Name),
				})
				continue
			}
			if res.Severity == checks.SeverityFail && strings.EqualFold(strings.TrimSpace(svc.Type), "container") && strings.TrimSpace(svc.ContainerName) != "" {
				targetHost := ""
				if hasHost {
					targetHost = host.Name
				}
				add(Suggestion{
					Action:     "restart_container",
					TargetHost: targetHost,
					Args:       []string{svc.ContainerName},
					Reason:     fmt.Sprintf("%s is container-backed and failing", svc.Name),
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
		return fmt.Sprintf("%s %s: %d failed, %d warning checks out of %d%s", report.Source, report.Env, report.FailCount, report.WarnCount, report.TotalChecks, suppressedSuffix(report.SuppressedCount))
	case "warn":
		return fmt.Sprintf("%s %s: %d warning checks out of %d%s", report.Source, report.Env, report.WarnCount, report.TotalChecks, suppressedSuffix(report.SuppressedCount))
	default:
		return fmt.Sprintf("%s %s: all %d checks passed%s", report.Source, report.Env, report.TotalChecks, suppressedSuffix(report.SuppressedCount))
	}
}

func buildHighlights(report Report) []string {
	active := append([]checks.Result(nil), report.FailedChecks...)
	active = append(active, report.WarningChecks...)
	sort.SliceStable(active, func(i, j int) bool {
		pi := resultPriority(active[i])
		pj := resultPriority(active[j])
		if pi == pj {
			if active[i].Severity == active[j].Severity {
				return active[i].Name < active[j].Name
			}
			return active[i].Severity == checks.SeverityFail
		}
		return pi < pj
	})
	limit := 4
	if len(active) < limit {
		limit = len(active)
	}
	out := make([]string, 0, limit)
	for i := 0; i < limit; i++ {
		item := active[i]
		out = append(out, fmt.Sprintf("%s [%s] %s", item.Name, item.Code, trimHighlight(item.Message)))
	}
	return out
}

func resultPriority(item checks.Result) int {
	switch {
	case strings.HasPrefix(item.Name, "host_ssh_"):
		return 0
	case strings.HasPrefix(item.Name, "service_runtime_"):
		return 1
	case strings.HasPrefix(item.Name, "service_logs_"):
		return 2
	case strings.HasPrefix(item.Name, "host_resource_"), strings.HasPrefix(item.Name, "host_process_"):
		return 3
	case strings.HasPrefix(item.Name, "service_"):
		return 4
	case strings.HasPrefix(item.Name, "dependency_"):
		return 5
	default:
		return 6
	}
}

func trimHighlight(v string) string {
	v = strings.TrimSpace(v)
	if len(v) <= 120 {
		return v
	}
	return v[:117] + "..."
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

func suppressedSuffix(n int) string {
	if n <= 0 {
		return ""
	}
	return fmt.Sprintf(", %d downstream checks suppressed", n)
}

func failingHosts(env config.Environment, results []checks.Result) map[string]suppression {
	checkToHost := map[string]config.Host{}
	for _, host := range env.Hosts {
		checkToHost["host_ssh_"+sanitizeName(host.Name)] = host
	}
	out := map[string]suppression{}
	for _, res := range results {
		if res.Severity != checks.SeverityFail {
			continue
		}
		host, ok := checkToHost[res.Name]
		if !ok {
			continue
		}
		out[host.Name] = suppression{
			SuppressedBy: res.Name,
			Reason:       "host SSH reachability failed",
		}
	}
	return out
}

func serviceHost(env config.Environment, svc config.Service) (config.Host, bool) {
	if ref := strings.TrimSpace(svc.Host); ref != "" {
		return env.HostByName(ref)
	}
	if rawURL := strings.TrimSpace(svc.HealthcheckURL); rawURL != "" {
		parsed, err := url.Parse(rawURL)
		if err == nil && parsed.Hostname() != "" {
			return env.HostByEndpoint(parsed.Hostname())
		}
	}
	return config.Host{}, false
}

func dependencyHosts(env config.Environment) map[string]string {
	out := map[string]string{}
	for _, dep := range env.Dependencies {
		dep = strings.TrimSpace(dep)
		scheme, host, port, err := config.ParseDependency(dep)
		if err != nil {
			continue
		}
		switch scheme {
		case "tcp":
			if envHost, ok := env.HostByEndpoint(host); ok {
				out["dependency_tcp_"+sanitizeName(net.JoinHostPort(host, port))] = envHost.Name
			}
		case "http", "https":
			parsed, err := url.Parse(dep)
			if err != nil || parsed.Hostname() == "" {
				continue
			}
			if envHost, ok := env.HostByEndpoint(parsed.Hostname()); ok {
				out["dependency_http_"+sanitizeName(depLabel(dep))] = envHost.Name
			}
		case "redis":
			if envHost, ok := env.HostByEndpoint(host); ok {
				out["dependency_redis_"+sanitizeName(net.JoinHostPort(host, port))] = envHost.Name
			}
		case "mysql":
			if envHost, ok := env.HostByEndpoint(host); ok {
				out["dependency_mysql_"+sanitizeName(net.JoinHostPort(host, port))] = envHost.Name
			}
		}
	}
	return out
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
