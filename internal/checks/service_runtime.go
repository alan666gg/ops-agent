package checks

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/alan666gg/ops-agent/internal/config"
)

type ContainerRuntimeChecker struct {
	NameLabel     string
	Host          config.Host
	ContainerName string
	Checks        config.ServiceChecks
	Timeout       time.Duration
	Runner        ScriptRunner
}

type SystemdJournalChecker struct {
	NameLabel string
	Host      config.Host
	Unit      string
	Checks    config.ServiceChecks
	Timeout   time.Duration
	Runner    ScriptRunner
}

type containerInspectSample struct {
	RestartCount int            `json:"restart_count"`
	State        containerState `json:"state"`
}

type containerState struct {
	Status     string `json:"status"`
	Running    bool   `json:"running"`
	Restarting bool   `json:"restarting"`
	OOMKilled  bool   `json:"oom_killed"`
	Error      string `json:"error"`
	ExitCode   int    `json:"exit_code"`
	StartedAt  string `json:"started_at"`
	FinishedAt string `json:"finished_at"`
}

func (c ContainerRuntimeChecker) Name() string {
	if c.NameLabel != "" {
		return c.NameLabel
	}
	return "service_runtime"
}

func (c ContainerRuntimeChecker) Run(ctx context.Context) Result {
	if strings.TrimSpace(c.Host.Host) == "" {
		return Result{Name: c.Name(), Code: "CONTAINER_HOST_MISSING", Message: "host address is empty", Action: "check service host mapping", Severity: SeverityWarn}
	}
	if strings.TrimSpace(c.ContainerName) == "" {
		return Result{Name: c.Name(), Code: "CONTAINER_NAME_MISSING", Message: "container name is empty", Action: "check discovery config", Severity: SeverityWarn}
	}
	timeout := c.Timeout
	if timeout <= 0 {
		timeout = 8 * time.Second
	}
	runner := c.Runner
	if runner == nil {
		runner = SSHScriptRunner{}
	}
	output, err := runner.RunScript(ctx, c.Host, timeout, buildContainerInspectScript(c.ContainerName))
	if err != nil {
		return Result{Name: c.Name(), Code: "CONTAINER_INSPECT_FAILED", Message: err.Error(), Action: "check docker daemon and container state", Severity: SeverityFail}
	}
	sample, err := parseContainerInspectSample(output)
	if err != nil {
		return Result{Name: c.Name(), Code: "CONTAINER_PARSE_FAILED", Message: err.Error(), Action: "check docker inspect output", Severity: SeverityWarn}
	}
	severity, code, message := evaluateContainerInspectSample(sample, c.Checks.WithDefaults(config.Service{Type: "container"}))
	return Result{Name: c.Name(), Code: code, Message: message, Action: "check container state, restarts, and logs", Severity: severity}
}

func (c SystemdJournalChecker) Name() string {
	if c.NameLabel != "" {
		return c.NameLabel
	}
	return "service_logs"
}

func (c SystemdJournalChecker) Run(ctx context.Context) Result {
	if strings.TrimSpace(c.Host.Host) == "" {
		return Result{Name: c.Name(), Code: "SYSTEMD_LOG_HOST_MISSING", Message: "host address is empty", Action: "check service host mapping", Severity: SeverityWarn}
	}
	if strings.TrimSpace(c.Unit) == "" {
		return Result{Name: c.Name(), Code: "SYSTEMD_LOG_UNIT_MISSING", Message: "systemd unit is empty", Action: "check discovery config", Severity: SeverityWarn}
	}
	timeout := c.Timeout
	if timeout <= 0 {
		timeout = 8 * time.Second
	}
	runner := c.Runner
	if runner == nil {
		runner = SSHScriptRunner{}
	}
	profile := c.Checks.WithDefaults(config.Service{Type: "systemd"})
	output, err := runner.RunScript(ctx, c.Host, timeout, buildSystemdJournalScript(c.Unit, profile.JournalWindow, profile.JournalLines))
	if err != nil {
		return Result{Name: c.Name(), Code: "SYSTEMD_LOGS_FAILED", Message: err.Error(), Action: "check journalctl availability and service logs", Severity: SeverityWarn}
	}
	lines := parseLogLines(output)
	if len(lines) > 0 {
		return Result{Name: c.Name(), Code: "SYSTEMD_RECENT_ERRORS", Message: "recent error logs: " + summarizeLogLines(lines, profile.JournalLines), Action: "inspect journal and service configuration", Severity: SeverityWarn}
	}
	return Result{Name: c.Name(), Code: "OK", Message: "no recent systemd error logs", Severity: SeverityPass}
}

func buildContainerInspectScript(container string) string {
	container = shellQuote(strings.TrimSpace(container))
	return strings.Join([]string{
		"set +e",
		"if ! command -v docker >/dev/null 2>&1; then echo 'docker binary missing'; exit 1; fi",
		"docker inspect --format '{\"restart_count\":{{.RestartCount}},\"state\":{\"status\":{{json .State.Status}},\"running\":{{json .State.Running}},\"restarting\":{{json .State.Restarting}},\"oom_killed\":{{json .State.OOMKilled}},\"error\":{{json .State.Error}},\"exit_code\":{{json .State.ExitCode}},\"started_at\":{{json .State.StartedAt}},\"finished_at\":{{json .State.FinishedAt}}}}' " + container,
	}, "\n")
}

func buildSystemdJournalScript(unit string, window time.Duration, lines int) string {
	unit = shellQuote(strings.TrimSpace(unit))
	return strings.Join([]string{
		"set +e",
		"if ! command -v journalctl >/dev/null 2>&1; then exit 0; fi",
		"journalctl -u " + unit + " -p err --since " + shellQuote(formatJournalSince(window)) + " -n " + fmt.Sprintf("%d", lines) + " --no-pager -o cat 2>/dev/null",
	}, "\n")
}

func parseContainerInspectSample(output string) (containerInspectSample, error) {
	var sample containerInspectSample
	if err := json.Unmarshal([]byte(strings.TrimSpace(output)), &sample); err != nil {
		return containerInspectSample{}, err
	}
	return sample, nil
}

func evaluateContainerInspectSample(sample containerInspectSample, checks config.ServiceChecks) (Severity, string, string) {
	status := strings.TrimSpace(sample.State.Status)
	if sample.State.OOMKilled {
		msg := fmt.Sprintf("oom_killed=true exit_code=%d", sample.State.ExitCode)
		if sample.State.Running {
			return SeverityWarn, "CONTAINER_OOMKILLED", msg + " (container recovered)"
		}
		return SeverityFail, "CONTAINER_OOMKILLED", msg
	}
	if sample.State.Restarting {
		return SeverityFail, "CONTAINER_RESTARTING", "container is restarting"
	}
	if !sample.State.Running || (status != "" && status != "running") {
		msg := "container status=" + defaultString(status, "unknown")
		if sample.State.ExitCode != 0 {
			msg += fmt.Sprintf(" exit_code=%d", sample.State.ExitCode)
		}
		if strings.TrimSpace(sample.State.FinishedAt) != "" {
			msg += " finished_at=" + trimTimestamp(sample.State.FinishedAt)
		}
		if strings.TrimSpace(sample.State.Error) != "" {
			msg += " error=" + strings.TrimSpace(sample.State.Error)
		}
		if sample.State.ExitCode != 0 {
			return SeverityFail, "CONTAINER_EXITED_NONZERO", msg
		}
		return SeverityFail, "CONTAINER_NOT_RUNNING", msg
	}
	if sample.RestartCount >= checks.RestartFailCount {
		return SeverityFail, "CONTAINER_FLAPPING", fmt.Sprintf("restart_count=%d exceeds fail threshold=%d started_at=%s", sample.RestartCount, checks.RestartFailCount, trimTimestamp(sample.State.StartedAt))
	}
	if sample.RestartCount >= checks.RestartWarnCount {
		return SeverityWarn, "CONTAINER_RESTARTS_WARN", fmt.Sprintf("restart_count=%d exceeds warn threshold=%d started_at=%s", sample.RestartCount, checks.RestartWarnCount, trimTimestamp(sample.State.StartedAt))
	}
	if sample.RestartCount > 0 {
		if startedAt, err := time.Parse(time.RFC3339Nano, strings.TrimSpace(sample.State.StartedAt)); err == nil && time.Since(startedAt) <= checks.RestartFlapWindow {
			return SeverityWarn, "CONTAINER_RECENT_RESTART", fmt.Sprintf("restart_count=%d and container restarted within %s started_at=%s", sample.RestartCount, checks.RestartFlapWindow, trimTimestamp(sample.State.StartedAt))
		}
	}
	return SeverityPass, "OK", fmt.Sprintf("container running restart_count=%d started_at=%s", sample.RestartCount, trimTimestamp(sample.State.StartedAt))
}

func formatJournalSince(window time.Duration) string {
	if window <= 0 {
		window = 30 * time.Minute
	}
	minutes := int(window.Minutes())
	if minutes < 1 {
		minutes = 1
	}
	return fmt.Sprintf("%d minutes ago", minutes)
}

func parseLogLines(output string) []string {
	var out []string
	for _, line := range strings.Split(strings.TrimSpace(output), "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			out = append(out, line)
		}
	}
	return out
}

func summarizeLogLines(lines []string, limit int) string {
	if len(lines) == 0 {
		return ""
	}
	type item struct {
		line  string
		count int
	}
	var items []item
	indexByLine := map[string]int{}
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if idx, ok := indexByLine[line]; ok {
			items[idx].count++
			continue
		}
		indexByLine[line] = len(items)
		items = append(items, item{line: line, count: 1})
	}
	if limit <= 0 {
		limit = 3
	}
	out := make([]string, 0, min(limit, len(items)))
	for i, item := range items {
		if i >= limit {
			break
		}
		line := trimForLog(item.line, 120)
		if item.count > 1 {
			line = fmt.Sprintf("[%dx] %s", item.count, line)
		}
		out = append(out, line)
	}
	if len(items) > limit {
		out = append(out, fmt.Sprintf("... and %d more unique errors", len(items)-limit))
	}
	return strings.Join(out, " | ")
}

func trimTimestamp(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "-"
	}
	if ts, err := time.Parse(time.RFC3339Nano, raw); err == nil {
		return ts.UTC().Format(time.RFC3339)
	}
	return raw
}

func trimForLog(v string, limit int) string {
	v = strings.TrimSpace(v)
	if limit <= 0 || len(v) <= limit {
		return v
	}
	if limit <= 3 {
		return v[:limit]
	}
	return v[:limit-3] + "..."
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
