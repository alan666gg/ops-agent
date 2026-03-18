package checks

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/alan666gg/ops-agent/internal/config"
)

type ScriptRunner interface {
	RunScript(ctx context.Context, host config.Host, timeout time.Duration, script string) (string, error)
}

type SSHScriptRunner struct{}

type RemoteHostResourceChecker struct {
	NameLabel string
	Host      config.Host
	Checks    config.HostChecks
	Timeout   time.Duration
	Runner    ScriptRunner
}

type RemoteProcessChecker struct {
	NameLabel string
	Host      config.Host
	Processes []string
	Timeout   time.Duration
	Runner    ScriptRunner
}

type hostResourceSample struct {
	Load1      float64
	CPUs       int
	MemoryUsed float64
	DiskUsed   float64
	InodeUsed  float64
	Filesystem string
}

func (SSHScriptRunner) RunScript(ctx context.Context, host config.Host, timeout time.Duration, script string) (string, error) {
	if strings.TrimSpace(host.Host) == "" {
		return "", fmt.Errorf("target host address is empty")
	}
	if timeout <= 0 {
		timeout = 8 * time.Second
	}
	runCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	args := append(buildSSHArgs(host), "sh", "-s")
	cmd := exec.CommandContext(runCtx, "ssh", args...)
	cmd.Stdin = strings.NewReader(script)
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("ssh script failed: %w: %s", err, strings.TrimSpace(out.String()))
	}
	return out.String(), nil
}

func (c RemoteHostResourceChecker) Name() string {
	if c.NameLabel != "" {
		return c.NameLabel
	}
	return "host_resource"
}

func (c RemoteHostResourceChecker) Run(ctx context.Context) Result {
	if strings.TrimSpace(c.Host.Host) == "" {
		return Result{Name: c.Name(), Code: "HOST_RESOURCE_HOST_MISSING", Message: "host address is empty", Action: "check host mapping", Severity: SeverityWarn}
	}
	profile := c.Checks.WithDefaults()
	timeout := c.Timeout
	if timeout <= 0 {
		timeout = 8 * time.Second
	}
	runner := c.Runner
	if runner == nil {
		runner = SSHScriptRunner{}
	}
	output, err := runner.RunScript(ctx, c.Host, timeout, buildResourceScript(profile.FilesystemPath))
	if err != nil {
		return Result{Name: c.Name(), Code: "HOST_RESOURCE_SSH_FAILED", Message: err.Error(), Action: "check host ssh and system load", Severity: SeverityFail}
	}
	sample, err := parseHostResourceSample(output)
	if err != nil {
		return Result{Name: c.Name(), Code: "HOST_RESOURCE_PARSE_FAILED", Message: err.Error(), Action: "check resource collection script output", Severity: SeverityWarn}
	}
	sample.Filesystem = profile.FilesystemPath
	severity, code, message := evaluateHostResourceSample(sample, profile)
	return Result{Name: c.Name(), Code: code, Message: message, Action: "check host load, memory, disk, and inode pressure", Severity: severity}
}

func (c RemoteProcessChecker) Name() string {
	if c.NameLabel != "" {
		return c.NameLabel
	}
	return "host_process"
}

func (c RemoteProcessChecker) Run(ctx context.Context) Result {
	if strings.TrimSpace(c.Host.Host) == "" {
		return Result{Name: c.Name(), Code: "HOST_PROCESS_HOST_MISSING", Message: "host address is empty", Action: "check host mapping", Severity: SeverityWarn}
	}
	processes := make([]string, 0, len(c.Processes))
	for _, process := range c.Processes {
		process = strings.TrimSpace(process)
		if process != "" {
			processes = append(processes, process)
		}
	}
	if len(processes) == 0 {
		return Result{Name: c.Name(), Code: "OK", Message: "no required processes configured", Severity: SeverityPass}
	}
	timeout := c.Timeout
	if timeout <= 0 {
		timeout = 8 * time.Second
	}
	runner := c.Runner
	if runner == nil {
		runner = SSHScriptRunner{}
	}
	output, err := runner.RunScript(ctx, c.Host, timeout, buildProcessScript(processes))
	if err != nil {
		return Result{Name: c.Name(), Code: "HOST_PROCESS_SSH_FAILED", Message: err.Error(), Action: "check host ssh and process supervision", Severity: SeverityFail}
	}
	missing := parseMissingProcesses(output)
	if len(missing) > 0 {
		return Result{Name: c.Name(), Code: "HOST_PROCESS_MISSING", Message: "missing required processes: " + strings.Join(missing, ", "), Action: "check process supervision or restart the service", Severity: SeverityFail}
	}
	return Result{Name: c.Name(), Code: "OK", Message: fmt.Sprintf("%d required processes present", len(processes)), Severity: SeverityPass}
}

func buildResourceScript(path string) string {
	path = shellQuote(defaultString(strings.TrimSpace(path), "/"))
	return strings.Join([]string{
		"set +e",
		`load1=$(awk '{print $1}' /proc/loadavg 2>/dev/null)`,
		`cpus=$(getconf _NPROCESSORS_ONLN 2>/dev/null || nproc 2>/dev/null || echo 1)`,
		`mem_pct=$(awk '/MemTotal:/ {t=$2} /MemAvailable:/ {a=$2} END { if (t>0) printf "%.2f", (1-(a/t))*100 }' /proc/meminfo 2>/dev/null)`,
		"disk_pct=$(df -P " + path + ` 2>/dev/null | awk 'NR==2 {gsub(/%/, "", $5); print $5}')`,
		"inode_pct=$(df -Pi " + path + ` 2>/dev/null | awk 'NR==2 {gsub(/%/, "", $5); print $5}')`,
		`printf 'load1=%s
cpus=%s
memory_used_percent=%s
disk_used_percent=%s
inode_used_percent=%s
' "$load1" "$cpus" "$mem_pct" "$disk_pct" "$inode_pct"`,
	}, "\n")
}

func buildProcessScript(processes []string) string {
	lines := []string{"set +e", "missing=''"}
	for _, process := range processes {
		q := shellQuote(process)
		lines = append(lines,
			"pattern="+q,
			"if ! pgrep -f -- \"$pattern\" >/dev/null 2>&1; then",
			"  if [ -n \"$missing\" ]; then missing=\"$missing,$pattern\"; else missing=\"$pattern\"; fi",
			"fi",
		)
	}
	lines = append(lines, `printf 'missing=%s
' "$missing"`)
	return strings.Join(lines, "\n")
}

func parseHostResourceSample(output string) (hostResourceSample, error) {
	values := map[string]string{}
	for _, line := range strings.Split(strings.TrimSpace(output), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		key, val, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		values[strings.TrimSpace(key)] = strings.TrimSpace(val)
	}
	var sample hostResourceSample
	var err error
	if sample.Load1, err = parseFloatValue(values["load1"]); err != nil {
		return hostResourceSample{}, fmt.Errorf("parse load1: %w", err)
	}
	if sample.CPUs, err = parseIntValue(values["cpus"]); err != nil {
		return hostResourceSample{}, fmt.Errorf("parse cpus: %w", err)
	}
	if sample.MemoryUsed, err = parseFloatValue(values["memory_used_percent"]); err != nil {
		return hostResourceSample{}, fmt.Errorf("parse memory_used_percent: %w", err)
	}
	if sample.DiskUsed, err = parseFloatValue(values["disk_used_percent"]); err != nil {
		return hostResourceSample{}, fmt.Errorf("parse disk_used_percent: %w", err)
	}
	if sample.InodeUsed, err = parseFloatValue(values["inode_used_percent"]); err != nil {
		return hostResourceSample{}, fmt.Errorf("parse inode_used_percent: %w", err)
	}
	if sample.CPUs <= 0 {
		sample.CPUs = 1
	}
	return sample, nil
}

func evaluateHostResourceSample(sample hostResourceSample, checks config.HostChecks) (Severity, string, string) {
	var warns []string
	var fails []string
	loadPerCPU := sample.Load1 / float64(max(sample.CPUs, 1))
	if loadPerCPU >= checks.LoadFailPerCPU {
		fails = append(fails, fmt.Sprintf("load/cpu=%.2f", loadPerCPU))
	} else if loadPerCPU >= checks.LoadWarnPerCPU {
		warns = append(warns, fmt.Sprintf("load/cpu=%.2f", loadPerCPU))
	}
	if sample.MemoryUsed >= checks.MemoryFailPercent {
		fails = append(fails, fmt.Sprintf("mem=%.1f%%", sample.MemoryUsed))
	} else if sample.MemoryUsed >= checks.MemoryWarnPercent {
		warns = append(warns, fmt.Sprintf("mem=%.1f%%", sample.MemoryUsed))
	}
	if sample.DiskUsed >= checks.DiskFailPercent {
		fails = append(fails, fmt.Sprintf("disk(%s)=%.0f%%", sample.Filesystem, sample.DiskUsed))
	} else if sample.DiskUsed >= checks.DiskWarnPercent {
		warns = append(warns, fmt.Sprintf("disk(%s)=%.0f%%", sample.Filesystem, sample.DiskUsed))
	}
	if sample.InodeUsed >= checks.InodeFailPercent {
		fails = append(fails, fmt.Sprintf("inode(%s)=%.0f%%", sample.Filesystem, sample.InodeUsed))
	} else if sample.InodeUsed >= checks.InodeWarnPercent {
		warns = append(warns, fmt.Sprintf("inode(%s)=%.0f%%", sample.Filesystem, sample.InodeUsed))
	}
	summary := fmt.Sprintf("load/cpu=%.2f mem=%.1f%% disk(%s)=%.0f%% inode(%s)=%.0f%%", loadPerCPU, sample.MemoryUsed, sample.Filesystem, sample.DiskUsed, sample.Filesystem, sample.InodeUsed)
	switch {
	case len(fails) > 0:
		return SeverityFail, "HOST_RESOURCE_FAIL", summary + "; failing: " + strings.Join(fails, ", ")
	case len(warns) > 0:
		return SeverityWarn, "HOST_RESOURCE_WARN", summary + "; warning: " + strings.Join(warns, ", ")
	default:
		return SeverityPass, "OK", summary
	}
}

func parseMissingProcesses(output string) []string {
	for _, line := range strings.Split(strings.TrimSpace(output), "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "missing=") {
			continue
		}
		raw := strings.TrimSpace(strings.TrimPrefix(line, "missing="))
		if raw == "" {
			return nil
		}
		parts := strings.Split(raw, ",")
		out := make([]string, 0, len(parts))
		for _, part := range parts {
			part = strings.TrimSpace(part)
			if part != "" {
				out = append(out, part)
			}
		}
		return out
	}
	return nil
}

func parseFloatValue(v string) (float64, error) {
	v = strings.TrimSpace(v)
	if v == "" {
		return 0, fmt.Errorf("value is empty")
	}
	return strconv.ParseFloat(v, 64)
}

func parseIntValue(v string) (int, error) {
	v = strings.TrimSpace(v)
	if v == "" {
		return 0, fmt.Errorf("value is empty")
	}
	return strconv.Atoi(v)
}

func shellQuote(v string) string {
	return "'" + strings.ReplaceAll(v, "'", `'"'"'`) + "'"
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
