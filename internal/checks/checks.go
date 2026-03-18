package checks

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os/exec"
	"runtime"
	"strings"
	"time"
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
	out := make([]Result, 0, len(r.items))
	for _, c := range r.items {
		out = append(out, c.Run(ctx))
	}
	return out
}

type HTTPChecker struct {
	TargetURL string
	Timeout   time.Duration
}

func (c HTTPChecker) Name() string { return "http_health" }

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
