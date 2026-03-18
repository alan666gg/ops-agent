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
	Error      string `json:"error"`
	StartedAt  string `json:"started_at"`
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
		return Result{Name: c.Name(), Code: "SYSTEMD_RECENT_ERRORS", Message: "recent error logs: " + strings.Join(lines, " | "), Action: "inspect journal and service configuration", Severity: SeverityWarn}
	}
	return Result{Name: c.Name(), Code: "OK", Message: "no recent systemd error logs", Severity: SeverityPass}
}

func buildContainerInspectScript(container string) string {
	container = shellQuote(strings.TrimSpace(container))
	return strings.Join([]string{
		"set +e",
		"if ! command -v docker >/dev/null 2>&1; then echo 'docker binary missing'; exit 1; fi",
		"docker inspect --format '{\"restart_count\":{{.RestartCount}},\"state\":{\"status\":{{json .State.Status}},\"running\":{{json .State.Running}},\"restarting\":{{json .State.Restarting}},\"error\":{{json .State.Error}},\"started_at\":{{json .State.StartedAt}}}}' " + container,
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
	if sample.State.Restarting {
		return SeverityFail, "CONTAINER_RESTARTING", "container is restarting"
	}
	if !sample.State.Running || (status != "" && status != "running") {
		msg := "container status=" + defaultString(status, "unknown")
		if strings.TrimSpace(sample.State.Error) != "" {
			msg += " error=" + strings.TrimSpace(sample.State.Error)
		}
		return SeverityFail, "CONTAINER_NOT_RUNNING", msg
	}
	if sample.RestartCount >= checks.RestartFailCount {
		return SeverityFail, "CONTAINER_FLAPPING", fmt.Sprintf("restart_count=%d exceeds fail threshold=%d", sample.RestartCount, checks.RestartFailCount)
	}
	if sample.RestartCount >= checks.RestartWarnCount {
		return SeverityWarn, "CONTAINER_RESTARTS_WARN", fmt.Sprintf("restart_count=%d exceeds warn threshold=%d", sample.RestartCount, checks.RestartWarnCount)
	}
	if sample.RestartCount > 0 {
		if startedAt, err := time.Parse(time.RFC3339Nano, strings.TrimSpace(sample.State.StartedAt)); err == nil && time.Since(startedAt) <= checks.RestartFlapWindow {
			return SeverityWarn, "CONTAINER_RECENT_RESTART", fmt.Sprintf("restart_count=%d and container restarted within %s", sample.RestartCount, checks.RestartFlapWindow)
		}
	}
	return SeverityPass, "OK", fmt.Sprintf("container running restart_count=%d", sample.RestartCount)
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
