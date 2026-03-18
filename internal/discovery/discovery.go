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
	SystemdUnit         string   `json:"systemd_unit,omitempty" yaml:"systemd_unit,omitempty"`
	ProcessName         string   `json:"process_name,omitempty" yaml:"process_name,omitempty"`
	ListenerPort        int      `json:"listener_port,omitempty" yaml:"listener_port,omitempty"`
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
	report.SuggestedService = suggestServices(host, containers, report.SystemdServices, report.Listeners)
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

func suggestServices(host config.Host, containers []Container, units []SystemdService, listeners []Listener) []ServiceCandidate {
	var out []ServiceCandidate
	containerPorts := map[int]bool{}
	usedListeners := map[string]bool{}
	for _, container := range containers {
		ports := publishedPorts(container.Ports)
		for _, port := range ports {
			containerPorts[port] = true
		}
		item := ServiceCandidate{
			Name:          sanitizeName(container.Name),
			Host:          strings.TrimSpace(host.Name),
			Type:          "container",
			ContainerName: container.Name,
			ListenerPort:  firstPort(ports),
		}
		item.CandidateHealthURLs = candidateHealthURLsForPorts(host.Host, ports)
		out = append(out, item)
	}

	byProcess := map[string][]Listener{}
	for _, listener := range listeners {
		process := listenerProcessName(listener.Process)
		if process == "" {
			continue
		}
		key := normalizeDaemonName(process)
		if key == "" {
			continue
		}
		byProcess[key] = append(byProcess[key], listener)
	}

	for _, unit := range units {
		base := systemdBaseName(unit.Name)
		if shouldIgnoreSystemd(base) {
			continue
		}
		matches := byProcess[normalizeDaemonName(base)]
		ports := listenerPorts(matches)
		item := ServiceCandidate{
			Name:         sanitizeName(base),
			Host:         strings.TrimSpace(host.Name),
			Type:         "systemd",
			SystemdUnit:  unit.Name,
			ProcessName:  base,
			ListenerPort: firstPort(ports),
		}
		if len(matches) > 0 {
			item.ProcessName = defaultString(listenerProcessName(matches[0].Process), base)
			item.CandidateHealthURLs = candidateHealthURLsForPorts(host.Host, ports)
			for _, listener := range matches {
				usedListeners[listenerKey(listener)] = true
			}
		}
		out = append(out, item)
	}

	for _, listener := range listeners {
		process := listenerProcessName(listener.Process)
		if containerPorts[listener.Port] || usedListeners[listenerKey(listener)] || shouldIgnoreListener(process, listener.Port) {
			continue
		}
		name := "listener-" + strconv.Itoa(listener.Port)
		if process != "" {
			name = sanitizeName(process + "-" + strconv.Itoa(listener.Port))
		}
		out = append(out, ServiceCandidate{
			Name:                name,
			Host:                strings.TrimSpace(host.Name),
			Type:                "listener",
			ProcessName:         process,
			ListenerPort:        listener.Port,
			CandidateHealthURLs: candidateHealthURLsForPorts(host.Host, []int{listener.Port}),
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

func candidateHealthURLs(host string, ports []string) []string {
	return candidateHealthURLsForPorts(host, publishedPorts(ports))
}

func candidateHealthURLsForPorts(host string, ports []int) []string {
	seen := map[string]bool{}
	var out []string
	for _, port := range ports {
		for _, scheme := range schemesForPort(port) {
			u := fmt.Sprintf("%s://%s:%d/", scheme, strings.TrimSpace(host), port)
			if !seen[u] {
				seen[u] = true
				out = append(out, u)
			}
		}
	}
	sort.Strings(out)
	return out
}

func publishedPorts(entries []string) []int {
	seen := map[int]bool{}
	var out []int
	for _, entry := range entries {
		for _, port := range extractPublishedPorts(entry) {
			if !seen[port] {
				seen[port] = true
				out = append(out, port)
			}
		}
	}
	sort.Ints(out)
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

func firstPort(ports []int) int {
	if len(ports) == 0 {
		return 0
	}
	return ports[0]
}

func listenerPorts(items []Listener) []int {
	seen := map[int]bool{}
	var out []int
	for _, item := range items {
		if item.Port <= 0 || seen[item.Port] {
			continue
		}
		seen[item.Port] = true
		out = append(out, item.Port)
	}
	sort.Ints(out)
	return out
}

func schemesForPort(port int) []string {
	switch port {
	case 443, 8443, 9443:
		return []string{"https", "http"}
	default:
		return []string{"http"}
	}
}

func listenerProcessName(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	if idx := strings.Index(raw, `"`); idx >= 0 {
		rest := raw[idx+1:]
		if end := strings.Index(rest, `"`); end >= 0 {
			return strings.TrimSpace(rest[:end])
		}
	}
	raw = strings.TrimPrefix(raw, "users:((")
	raw = strings.TrimSuffix(raw, "))")
	if idx := strings.Index(raw, ","); idx >= 0 {
		raw = raw[:idx]
	}
	raw = strings.Trim(raw, `"'() `)
	return strings.TrimSpace(raw)
}

func systemdBaseName(unit string) string {
	unit = strings.TrimSpace(unit)
	unit = strings.TrimSuffix(unit, ".service")
	if idx := strings.Index(unit, "@"); idx >= 0 {
		unit = unit[:idx]
	}
	return unit
}

func normalizeDaemonName(v string) string {
	v = strings.ToLower(strings.TrimSpace(v))
	var b strings.Builder
	for _, r := range v {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
		}
	}
	return b.String()
}

func shouldIgnoreSystemd(unit string) bool {
	norm := normalizeDaemonName(unit)
	if norm == "" {
		return true
	}
	prefixes := []string{
		"dbus",
		"systemd",
		"getty",
		"serialgetty",
		"user",
		"cron",
		"crond",
		"sshd",
		"rsyslog",
		"polkit",
		"network",
		"containerd",
		"docker",
		"kubelet",
		"snapd",
		"udisks",
		"wpasupplicant",
		"multipath",
		"nscd",
	}
	for _, prefix := range prefixes {
		if strings.HasPrefix(norm, prefix) {
			return true
		}
	}
	return false
}

func shouldIgnoreListener(process string, port int) bool {
	if port == 22 {
		return true
	}
	if port < 1024 && port != 80 && port != 443 {
		return true
	}
	norm := normalizeDaemonName(process)
	if norm == "" {
		return false
	}
	ignored := map[string]bool{
		"sshd":            true,
		"dockerproxy":     true,
		"containerd":      true,
		"systemd":         true,
		"systemdresolved": true,
		"kubeproxy":       true,
		"nodeexporter":    true,
		"prometheus":      true,
	}
	return ignored[norm]
}

func listenerKey(item Listener) string {
	return strconv.Itoa(item.Port) + "|" + normalizeDaemonName(listenerProcessName(item.Process))
}

func defaultString(v, fallback string) string {
	if strings.TrimSpace(v) == "" {
		return fallback
	}
	return v
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
