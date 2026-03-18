package checks

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/alan666gg/ops-agent/internal/config"
)

type Severity string

const (
	SeverityPass Severity = "pass"
	SeverityWarn Severity = "warn"
	SeverityFail Severity = "fail"
)

type Result struct {
	Name     string   `json:"name"`
	Code     string   `json:"code"`
	Message  string   `json:"message"`
	Action   string   `json:"action,omitempty"`
	Severity Severity `json:"severity"`
}

type Checker interface {
	Name() string
	Run(ctx context.Context) Result
}

type Registry struct {
	items []Checker
}

func NewRegistry(items ...Checker) Registry {
	return Registry{items: items}
}

func (r Registry) RunAll(ctx context.Context) []Result {
	if len(r.items) == 0 {
		return nil
	}
	out := make([]Result, len(r.items))
	var wg sync.WaitGroup
	wg.Add(len(r.items))
	for i, c := range r.items {
		go func(i int, c Checker) {
			defer wg.Done()
			out[i] = c.Run(ctx)
		}(i, c)
	}
	wg.Wait()
	return out
}

type HTTPChecker struct {
	NameLabel string
	TargetURL string
	Timeout   time.Duration
}

func (c HTTPChecker) Name() string {
	if c.NameLabel != "" {
		return c.NameLabel
	}
	return "http_health"
}

func (c HTTPChecker) Run(ctx context.Context) Result {
	t := c.Timeout
	if t <= 0 {
		t = 5 * time.Second
	}
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, c.TargetURL, nil)
	client := &http.Client{Timeout: t}
	resp, err := client.Do(req)
	if err != nil {
		return Result{Name: c.Name(), Code: "HTTP_DOWN", Message: err.Error(), Action: "check service/container and endpoint", Severity: SeverityFail}
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return Result{Name: c.Name(), Code: "HTTP_BAD_STATUS", Message: fmt.Sprintf("status=%d", resp.StatusCode), Action: "inspect logs and upstream deps", Severity: SeverityWarn}
	}
	return Result{Name: c.Name(), Code: "OK", Message: "service reachable", Severity: SeverityPass}
}

type TCPChecker struct {
	NameLabel string
	Host      string
	Port      string
	Timeout   time.Duration
}

func (c TCPChecker) Name() string {
	if c.NameLabel != "" {
		return c.NameLabel
	}
	return "tcp_dependency"
}

func (c TCPChecker) Run(ctx context.Context) Result {
	t := c.Timeout
	if t <= 0 {
		t = 3 * time.Second
	}
	d := net.Dialer{Timeout: t}
	conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(c.Host, c.Port))
	if err != nil {
		return Result{Name: c.Name(), Code: "TCP_UNREACHABLE", Message: err.Error(), Action: "check dependency host/port/network", Severity: SeverityFail}
	}
	_ = conn.Close()
	return Result{Name: c.Name(), Code: "OK", Message: "dependency reachable", Severity: SeverityPass}
}

type HostChecker struct{}

func (HostChecker) Name() string { return "host_basics" }

func (HostChecker) Run(ctx context.Context) Result {
	_ = ctx
	cmd := "uptime"
	if runtime.GOOS == "windows" {
		cmd = "ver"
	}
	if _, err := exec.LookPath(strings.Split(cmd, " ")[0]); err != nil {
		return Result{Name: "host_basics", Code: "HOST_TOOL_MISSING", Message: err.Error(), Action: "install basic host tooling", Severity: SeverityWarn}
	}
	return Result{Name: "host_basics", Code: "OK", Message: "host toolchain present", Severity: SeverityPass}
}

type SystemdUnitChecker struct {
	NameLabel string
	Host      config.Host
	Unit      string
	Timeout   time.Duration
}

func (c SystemdUnitChecker) Name() string {
	if c.NameLabel != "" {
		return c.NameLabel
	}
	return "systemd_service"
}

func (c SystemdUnitChecker) Run(ctx context.Context) Result {
	if strings.TrimSpace(c.Host.Host) == "" {
		return Result{Name: c.Name(), Code: "SYSTEMD_HOST_MISSING", Message: "host address is empty", Action: "check service host mapping", Severity: SeverityWarn}
	}
	if strings.TrimSpace(c.Unit) == "" {
		return Result{Name: c.Name(), Code: "SYSTEMD_UNIT_MISSING", Message: "systemd unit is empty", Action: "check discovery config", Severity: SeverityWarn}
	}
	t := c.Timeout
	if t <= 0 {
		t = 5 * time.Second
	}
	checkCtx, cancel := context.WithTimeout(ctx, t)
	defer cancel()
	args := append(buildSSHArgs(c.Host), "systemctl", "is-active", c.Unit)
	cmd := exec.CommandContext(checkCtx, "ssh", args...)
	out, err := cmd.CombinedOutput()
	status := strings.TrimSpace(string(out))
	if err != nil {
		msg := defaultString(status, err.Error())
		return Result{Name: c.Name(), Code: "SYSTEMD_CHECK_FAILED", Message: msg, Action: "check systemd status and journal", Severity: SeverityFail}
	}
	if status != "active" {
		return Result{Name: c.Name(), Code: "SYSTEMD_INACTIVE", Message: defaultString(status, "inactive"), Action: "check systemd status and journal", Severity: SeverityFail}
	}
	return Result{Name: c.Name(), Code: "OK", Message: "systemd service active", Severity: SeverityPass}
}

func buildSSHArgs(host config.Host) []string {
	port := host.SSHPort
	if port <= 0 {
		port = 22
	}
	dest := strings.TrimSpace(host.Host)
	if user := strings.TrimSpace(host.SSHUser); user != "" {
		dest = user + "@" + dest
	}
	return []string{"-p", strconv.Itoa(port), dest}
}

func defaultString(v, fallback string) string {
	if strings.TrimSpace(v) == "" {
		return fallback
	}
	return v
}
