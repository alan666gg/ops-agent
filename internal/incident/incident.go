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
	Strategy         string   `json:"strategy,omitempty"`
	Reason           string   `json:"reason"`
	RequiresApproval bool     `json:"requires_approval"`
}

type ReportContext struct {
	RecentChanges []TimelineEntry `json:"recent_changes,omitempty"`
}

type SuppressedCheck struct {
	Result       checks.Result `json:"result"`
	SuppressedBy string        `json:"suppressed_by"`
	Reason       string        `json:"reason"`
}

type ExternalAlert struct {
	Provider     string            `json:"provider"`
	Receiver     string            `json:"receiver,omitempty"`
	AlertName    string            `json:"alert_name,omitempty"`
	Fingerprint  string            `json:"fingerprint,omitempty"`
	Labels       map[string]string `json:"labels,omitempty"`
	Annotations  map[string]string `json:"annotations,omitempty"`
	GeneratorURL string            `json:"generator_url,omitempty"`
	ExternalURL  string            `json:"external_url,omitempty"`
	StartsAt     time.Time         `json:"starts_at,omitempty"`
	EndsAt       time.Time         `json:"ends_at,omitempty"`
}

type ExternalSilence struct {
	ID        string    `json:"id"`
	Status    string    `json:"status,omitempty"`
	CreatedBy string    `json:"created_by,omitempty"`
	Comment   string    `json:"comment,omitempty"`
	StartsAt  time.Time `json:"starts_at,omitempty"`
	EndsAt    time.Time `json:"ends_at,omitempty"`
	ExpiredAt time.Time `json:"expired_at,omitempty"`
	ExpiredBy string    `json:"expired_by,omitempty"`
	UpdatedAt time.Time `json:"updated_at,omitempty"`
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
	External         *ExternalAlert    `json:"external,omitempty"`
	RecentChanges    []TimelineEntry   `json:"recent_changes,omitempty"`
	Suggestions      []Suggestion      `json:"suggestions,omitempty"`
	FailCount        int               `json:"fail_count"`
	WarnCount        int               `json:"warn_count"`
	SuppressedCount  int               `json:"suppressed_count"`
	TotalChecks      int               `json:"total_checks"`
	FailedChecks     []checks.Result   `json:"failed_checks,omitempty"`
	WarningChecks    []checks.Result   `json:"warning_checks,omitempty"`
	SuppressedChecks []SuppressedCheck `json:"suppressed_checks,omitempty"`
}

func SilenceStatus(silence *ExternalSilence, now time.Time) string {
	if silence == nil {
		return ""
	}
	status := strings.ToLower(strings.TrimSpace(silence.Status))
	if !silence.ExpiredAt.IsZero() {
		return "expired"
	}
	if !silence.EndsAt.IsZero() && !now.IsZero() && !now.Before(silence.EndsAt) {
		return "expired"
	}
	if status != "" {
		return status
	}
	return "active"
}

func SilenceActive(silence *ExternalSilence, now time.Time) bool {
	return SilenceStatus(silence, now) == "active"
}

func BuildReport(source, envName string, env config.Environment, results []checks.Result, policyCfg policy.Config, recentAutoActions int) Report {
	return BuildReportWithContext(source, envName, env, results, policyCfg, recentAutoActions, ReportContext{})
}

func BuildReportWithContext(source, envName string, env config.Environment, results []checks.Result, policyCfg policy.Config, recentAutoActions int, ctx ReportContext) Report {
	report := Report{
		Source:      source,
		Project:     env.ProjectName(),
		Env:         envName,
		Status:      "ok",
		TriggeredAt: time.Now().UTC(),
		Results:     append([]checks.Result(nil), results...),
		TotalChecks: len(results),
	}
	report.RecentChanges = trimRecentChanges(ctx.RecentChanges, 3)
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

	report.Suggestions = BuildSuggestionsWithContext(envName, env, actionable, policyCfg, recentAutoActions, ctx)
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
	return BuildSuggestionsWithContext(envName, env, results, policyCfg, recentAutoActions, ReportContext{})
}

func BuildSuggestionsWithContext(envName string, env config.Environment, results []checks.Result, policyCfg policy.Config, recentAutoActions int, ctx ReportContext) []Suggestion {
	var out []Suggestion
	seen := map[string]int{}
	hostByKey := map[string]config.Host{}
	depByKey := map[string]string{}
	serviceNameByCheck := map[string]string{}
	serviceResults := map[string][]checks.Result{}

	for _, svc := range env.Services {
		suffix := sanitizeName(svc.Name)
		serviceNameByCheck["service_"+suffix] = svc.Name
		serviceNameByCheck["service_runtime_"+suffix] = svc.Name
		serviceNameByCheck["service_logs_"+suffix] = svc.Name
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
		if idx, ok := seen[key]; ok {
			out[idx] = mergeSuggestion(out[idx], s)
			return
		}
		seen[key] = len(out)
		decision := policyCfg.Evaluate(s.Action, envName, recentAutoActions)
		s.RequiresApproval = decision.RequiresApproval
		out = append(out, s)
	}

	for _, res := range results {
		if res.Severity == checks.SeverityPass {
			continue
		}
		if svcName, ok := serviceNameByCheck[res.Name]; ok {
			serviceResults[svcName] = append(serviceResults[svcName], res)
			continue
		}
		if host, ok := hostByKey[res.Name]; ok {
			add(Suggestion{
				Action:     "check_host_health",
				Strategy:   "investigate",
				TargetHost: host.Name,
				Reason:     fmt.Sprintf("%s: %s", res.Name, res.Message),
			})
			continue
		}
		if dep, ok := depByKey[res.Name]; ok {
			add(Suggestion{
				Action:   "check_dependencies",
				Args:     []string{dep},
				Strategy: "dependency",
				Reason:   fmt.Sprintf("%s: %s", res.Name, res.Message),
			})
			continue
		}
		if res.Name == "host_basics" {
			add(Suggestion{
				Action:   "check_host_health",
				Strategy: "investigate",
				Reason:   fmt.Sprintf("%s: %s", res.Name, res.Message),
			})
		}
	}

	for _, svc := range env.Services {
		items := serviceResults[svc.Name]
		if len(items) == 0 {
			continue
		}
		host, hasHost := serviceHost(env, svc)
		change := latestRelevantChange(ctx.RecentChanges, svc, host, hasHost)
		changeHint := formatChangeHint(change)
		if strings.TrimSpace(svc.HealthcheckURL) != "" {
			strategy := "investigate"
			reason := fmt.Sprintf("%s reported service health failures", svc.Name)
			if change != nil {
				strategy = "change_regression"
				reason = fmt.Sprintf("%s started failing near %s; inspect release/config drift before restart", svc.Name, changeHint)
			}
			add(Suggestion{
				Action:   "check_service_health",
				Args:     []string{svc.HealthcheckURL},
				Strategy: strategy,
				Reason:   reason,
			})
		}
		if hasHost {
			switch serviceRemediationStrategy(items, change) {
			case "capacity":
				add(Suggestion{
					Action:     "check_host_health",
					TargetHost: host.Name,
					Strategy:   "capacity",
					Reason:     fmt.Sprintf("%s on %s shows OOM or restart pressure; inspect host capacity before restart", svc.Name, host.Name),
				})
			case "change_regression":
				add(Suggestion{
					Action:     "check_host_health",
					TargetHost: host.Name,
					Strategy:   "change_regression",
					Reason:     fmt.Sprintf("%s on %s started failing near %s; inspect rollout and rollback readiness", svc.Name, host.Name, changeHint),
				})
			case "investigate":
				if hasSystemdErrors(items) || hasRuntimeInstability(items) {
					add(Suggestion{
						Action:     "check_host_health",
						TargetHost: host.Name,
						Strategy:   "investigate",
						Reason:     fmt.Sprintf("%s on %s needs runtime inspection before restart", svc.Name, host.Name),
					})
				}
			}
		}
		if strings.EqualFold(strings.TrimSpace(svc.Type), "container") && strings.TrimSpace(svc.ContainerName) != "" && shouldRestartContainer(items, change) {
			targetHost := ""
			if hasHost {
				targetHost = host.Name
			}
			add(Suggestion{
				Action:     "restart_container",
				TargetHost: targetHost,
				Args:       []string{svc.ContainerName},
				Strategy:   "restart_candidate",
				Reason:     fmt.Sprintf("%s is stopped without strong change/capacity signals; restart is a reasonable next step", svc.Name),
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
	if report.Status != "ok" && len(report.RecentChanges) > 0 {
		out = append(out, "recent change "+formatChangeHint(&report.RecentChanges[0]))
	}
	for i := 0; i < limit; i++ {
		item := active[i]
		out = append(out, fmt.Sprintf("%s [%s] %s", item.Name, item.Code, trimHighlight(item.Message)))
	}
	if len(out) > 4 {
		out = out[:4]
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

func latestRelevantChange(changes []TimelineEntry, svc config.Service, host config.Host, hasHost bool) *TimelineEntry {
	for i := range changes {
		if changeMatchesService(changes[i], svc, host, hasHost) {
			return &changes[i]
		}
	}
	return nil
}

func changeMatchesService(change TimelineEntry, svc config.Service, host config.Host, hasHost bool) bool {
	fields := []string{
		strings.ToLower(strings.TrimSpace(change.Target)),
		strings.ToLower(strings.TrimSpace(change.Message)),
		strings.ToLower(strings.TrimSpace(change.Reference)),
	}
	tokens := []string{
		strings.ToLower(strings.TrimSpace(svc.Name)),
		strings.ToLower(strings.TrimSpace(svc.ContainerName)),
		strings.ToLower(strings.TrimSpace(svc.SystemdUnit)),
	}
	if hasHost {
		tokens = append(tokens, strings.ToLower(strings.TrimSpace(host.Name)), strings.ToLower(strings.TrimSpace(host.Host)))
	}
	for _, token := range tokens {
		if token == "" {
			continue
		}
		for _, field := range fields {
			if field != "" && strings.Contains(field, token) {
				return true
			}
		}
	}
	return false
}

func serviceRemediationStrategy(items []checks.Result, change *TimelineEntry) string {
	if hasCode(items, "CONTAINER_OOMKILLED") {
		return "capacity"
	}
	if change != nil && (hasRuntimeInstability(items) || hasSystemdErrors(items) || hasHealthFailures(items) || hasCode(items, "CONTAINER_NOT_RUNNING") || hasCode(items, "CONTAINER_EXITED_NONZERO")) {
		return "change_regression"
	}
	if hasRuntimeInstability(items) || hasSystemdErrors(items) {
		return "investigate"
	}
	return ""
}

func shouldRestartContainer(items []checks.Result, change *TimelineEntry) bool {
	if change != nil {
		return false
	}
	if hasCode(items, "CONTAINER_OOMKILLED") || hasCode(items, "CONTAINER_FLAPPING") || hasCode(items, "CONTAINER_RESTARTS_WARN") || hasCode(items, "CONTAINER_RECENT_RESTART") || hasCode(items, "CONTAINER_RESTARTING") {
		return false
	}
	return hasCode(items, "CONTAINER_NOT_RUNNING") || hasCode(items, "CONTAINER_EXITED_NONZERO")
}

func hasRuntimeInstability(items []checks.Result) bool {
	for _, item := range items {
		if strings.HasPrefix(item.Code, "CONTAINER_") && item.Code != "CONTAINER_NOT_RUNNING" && item.Code != "CONTAINER_EXITED_NONZERO" && item.Code != "OK" {
			return true
		}
	}
	return false
}

func hasSystemdErrors(items []checks.Result) bool {
	return hasCode(items, "SYSTEMD_RECENT_ERRORS")
}

func hasHealthFailures(items []checks.Result) bool {
	for _, item := range items {
		if strings.HasPrefix(item.Name, "service_") && !strings.HasPrefix(item.Name, "service_runtime_") && !strings.HasPrefix(item.Name, "service_logs_") {
			return true
		}
	}
	return false
}

func hasCode(items []checks.Result, code string) bool {
	for _, item := range items {
		if strings.EqualFold(strings.TrimSpace(item.Code), strings.TrimSpace(code)) {
			return true
		}
	}
	return false
}

func formatChangeHint(change *TimelineEntry) string {
	if change == nil {
		return "recent change"
	}
	parts := []string{strings.TrimSpace(change.Action)}
	if strings.TrimSpace(change.Reference) != "" {
		parts = append(parts, "ref="+change.Reference)
	}
	if strings.TrimSpace(change.Revision) != "" {
		parts = append(parts, "rev="+change.Revision)
	}
	if strings.TrimSpace(change.Target) != "" {
		parts = append(parts, "target="+change.Target)
	}
	return strings.Join(parts, " ")
}

func trimRecentChanges(items []TimelineEntry, limit int) []TimelineEntry {
	if limit <= 0 || len(items) <= limit {
		return append([]TimelineEntry(nil), items...)
	}
	return append([]TimelineEntry(nil), items[:limit]...)
}

func mergeSuggestion(existing, next Suggestion) Suggestion {
	if strings.TrimSpace(next.Strategy) != "" && strategyRank(next.Strategy) > strategyRank(existing.Strategy) {
		existing.Strategy = next.Strategy
	}
	if strings.TrimSpace(next.Reason) != "" && !strings.Contains(existing.Reason, next.Reason) {
		if strings.TrimSpace(existing.Reason) == "" {
			existing.Reason = next.Reason
		} else {
			existing.Reason += "; " + next.Reason
		}
	}
	if existing.TargetHost == "" {
		existing.TargetHost = next.TargetHost
	}
	if len(existing.Args) == 0 && len(next.Args) > 0 {
		existing.Args = append([]string(nil), next.Args...)
	}
	existing.RequiresApproval = existing.RequiresApproval || next.RequiresApproval
	return existing
}

func strategyRank(v string) int {
	switch strings.TrimSpace(v) {
	case "change_regression":
		return 4
	case "capacity":
		return 3
	case "restart_candidate":
		return 2
	case "dependency":
		return 1
	default:
		return 0
	}
}
