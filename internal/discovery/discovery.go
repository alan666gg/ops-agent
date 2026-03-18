package discovery

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/alan666gg/ops-agent/internal/config"
)

type Runner interface {
	Run(ctx context.Context, host config.Host, timeout time.Duration) (string, error)
}

type SSHRunner struct{}

type Report struct {
	GeneratedAt      time.Time          `json:"generated_at" yaml:"generated_at"`
	HostName         string             `json:"host_name" yaml:"host_name"`
	HostAddress      string             `json:"host_address" yaml:"host_address"`
	Containers       []Container        `json:"containers,omitempty" yaml:"containers,omitempty"`
	SystemdServices  []SystemdService   `json:"systemd_services,omitempty" yaml:"systemd_services,omitempty"`
	Listeners        []Listener         `json:"listeners,omitempty" yaml:"listeners,omitempty"`
	SuggestedService []ServiceCandidate `json:"suggested_services,omitempty" yaml:"suggested_services,omitempty"`
}

type Container struct {
	Name   string   `json:"name" yaml:"name"`
	Image  string   `json:"image" yaml:"image"`
	Status string   `json:"status" yaml:"status"`
	Ports  []string `json:"ports,omitempty" yaml:"ports,omitempty"`
}

type SystemdService struct {
	Name        string `json:"name" yaml:"name"`
	Load        string `json:"load,omitempty" yaml:"load,omitempty"`
	Active      string `json:"active,omitempty" yaml:"active,omitempty"`
	Sub         string `json:"sub,omitempty" yaml:"sub,omitempty"`
	Description string `json:"description,omitempty" yaml:"description,omitempty"`
}

type Listener struct {
	Proto   string `json:"proto" yaml:"proto"`
	Address string `json:"address" yaml:"address"`
	Port    int    `json:"port" yaml:"port"`
	Process string `json:"process,omitempty" yaml:"process,omitempty"`
}

type ServiceCandidate struct {
	Name                string   `json:"name" yaml:"name"`
	Host                string   `json:"host" yaml:"host"`
	Type                string   `json:"type" yaml:"type"`
	ContainerName       string   `json:"container_name,omitempty" yaml:"container_name,omitempty"`
	CandidateHealthURLs []string `json:"candidate_health_urls,omitempty" yaml:"candidate_health_urls,omitempty"`
}

const script = `set +e
echo '@@SECTION:docker@@'
if command -v docker >/dev/null 2>&1; then
  docker ps --format '{{json .}}'
fi
echo '@@SECTION:systemd@@'
if command -v systemctl >/dev/null 2>&1; then
  systemctl list-units --type=service --state=running --no-legend --no-pager --plain
fi
echo '@@SECTION:listeners@@'
if command -v ss >/dev/null 2>&1; then
  ss -lntpH
elif command -v netstat >/dev/null 2>&1; then
  netstat -lntp 2>/dev/null | awk 'NR>2{print}'
fi
`

func Discover(ctx context.Context, host config.Host, timeout time.Duration, runner Runner) (Report, error) {
	if runner == nil {
		runner = SSHRunner{}
	}
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	output, err := runner.Run(ctx, host, timeout)
	if err != nil {
		return Report{}, err
	}
	report, err := Parse(strings.TrimSpace(output), host)
	if err != nil {
		return Report{}, err
	}
	return report, nil
}

func (SSHRunner) Run(ctx context.Context, host config.Host, timeout time.Duration) (string, error) {
	if strings.TrimSpace(host.Host) == "" {
		return "", fmt.Errorf("target host address is empty")
	}
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	cctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	cmd := exec.CommandContext(cctx, "ssh", buildSSHArgs(host)...)
	cmd.Stdin = strings.NewReader(script)
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	err := cmd.Run()
	if err != nil {
		return "", fmt.Errorf("ssh discovery failed: %w: %s", err, strings.TrimSpace(out.String()))
	}
	return out.String(), nil
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
	return []string{"-p", strconv.Itoa(port), dest, "sh", "-s"}
}

func Parse(output string, host config.Host) (Report, error) {
	sections := splitSections(output)
	report := Report{
		GeneratedAt: time.Now().UTC(),
		HostName:    strings.TrimSpace(host.Name),
		HostAddress: strings.TrimSpace(host.Host),
	}
	containers, err := parseContainers(sections["docker"])
	if err != nil {
		return Report{}, err
	}
	report.Containers = containers
	report.SystemdServices = parseSystemd(sections["systemd"])
	report.Listeners = parseListeners(sections["listeners"])
	report.SuggestedService = suggestServices(host, containers)
	return report, nil
}

func splitSections(output string) map[string][]string {
	out := map[string][]string{}
	current := ""
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "@@SECTION:") && strings.HasSuffix(line, "@@") {
			current = strings.TrimSuffix(strings.TrimPrefix(line, "@@SECTION:"), "@@")
			continue
		}
		if current != "" {
			out[current] = append(out[current], line)
		}
	}
	return out
}

func parseContainers(lines []string) ([]Container, error) {
	type dockerRow struct {
		Names  string `json:"Names"`
		Image  string `json:"Image"`
		Status string `json:"Status"`
		Ports  string `json:"Ports"`
	}
	var out []Container
	for _, line := range lines {
		var row dockerRow
		if err := json.Unmarshal([]byte(line), &row); err != nil {
			return nil, fmt.Errorf("parse docker discovery row: %w", err)
		}
		item := Container{
			Name:   strings.TrimSpace(row.Names),
			Image:  strings.TrimSpace(row.Image),
			Status: strings.TrimSpace(row.Status),
			Ports:  splitPorts(row.Ports),
		}
		if item.Name != "" {
			out = append(out, item)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

func parseSystemd(lines []string) []SystemdService {
	var out []SystemdService
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}
		item := SystemdService{
			Name:   fields[0],
			Load:   fields[1],
			Active: fields[2],
			Sub:    fields[3],
		}
		if len(fields) > 4 {
			item.Description = strings.Join(fields[4:], " ")
		}
		out = append(out, item)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

func parseListeners(lines []string) []Listener {
	seen := map[string]bool{}
	var out []Listener
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) < 5 {
			continue
		}
		local := fields[3]
		addr, port, ok := splitHostPort(local)
		if !ok {
			continue
		}
		item := Listener{
			Proto:   "tcp",
			Address: addr,
			Port:    port,
		}
		if len(fields) > 5 {
			item.Process = strings.Join(fields[5:], " ")
		}
		key := fmt.Sprintf("%s:%d:%s", item.Address, item.Port, item.Process)
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, item)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Port == out[j].Port {
			return out[i].Address < out[j].Address
		}
		return out[i].Port < out[j].Port
	})
	return out
}

func splitHostPort(v string) (string, int, bool) {
	v = strings.TrimSpace(v)
	if v == "" {
		return "", 0, false
	}
	if idx := strings.LastIndex(v, ":"); idx >= 0 {
		host := strings.Trim(v[:idx], "[]")
		port, err := strconv.Atoi(strings.TrimSpace(v[idx+1:]))
		if err != nil {
			return "", 0, false
		}
		return host, port, true
	}
	return "", 0, false
}

func splitPorts(raw string) []string {
	var out []string
	for _, item := range strings.Split(strings.TrimSpace(raw), ",") {
		item = strings.TrimSpace(item)
		if item != "" {
			out = append(out, item)
		}
	}
	return out
}

func suggestServices(host config.Host, containers []Container) []ServiceCandidate {
	var out []ServiceCandidate
	for _, container := range containers {
		item := ServiceCandidate{
			Name:          sanitizeName(container.Name),
			Host:          strings.TrimSpace(host.Name),
			Type:          "container",
			ContainerName: container.Name,
		}
		item.CandidateHealthURLs = candidateHealthURLs(host.Host, container.Ports)
		out = append(out, item)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

func candidateHealthURLs(host string, ports []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, entry := range ports {
		for _, port := range extractPublishedPorts(entry) {
			u := fmt.Sprintf("http://%s:%d/", strings.TrimSpace(host), port)
			if !seen[u] {
				seen[u] = true
				out = append(out, u)
			}
		}
	}
	sort.Strings(out)
	return out
}

func extractPublishedPorts(entry string) []int {
	var out []int
	for _, token := range strings.Split(entry, ",") {
		token = strings.TrimSpace(token)
		if token == "" || !strings.Contains(token, "->") {
			continue
		}
		left := strings.TrimSpace(strings.SplitN(token, "->", 2)[0])
		if idx := strings.LastIndex(left, ":"); idx >= 0 {
			left = left[idx+1:]
		}
		port, err := strconv.Atoi(strings.TrimSpace(left))
		if err == nil && port > 0 {
			out = append(out, port)
		}
	}
	sort.Ints(out)
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
			b.WriteRune(r + ('a' - 'A'))
		case r >= '0' && r <= '9':
			b.WriteRune(r)
		default:
			b.WriteByte('-')
		}
	}
	return strings.Trim(b.String(), "-")
}
