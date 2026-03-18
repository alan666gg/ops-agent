package config

import (
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

type EnvironmentFile struct {
	Environments map[string]Environment `yaml:"environments"`
}

type Environment struct {
	Project      string    `yaml:"project,omitempty"`
	Hosts        []Host    `yaml:"hosts"`
	Services     []Service `yaml:"services"`
	Dependencies []string  `yaml:"dependencies"`
}

type Host struct {
	Name    string     `yaml:"name"`
	Host    string     `yaml:"host"`
	SSHUser string     `yaml:"ssh_user"`
	SSHPort int        `yaml:"ssh_port"`
	Checks  HostChecks `yaml:"checks,omitempty"`
}

type HostChecks struct {
	LoadWarnPerCPU    float64  `yaml:"load_warn_per_cpu,omitempty"`
	LoadFailPerCPU    float64  `yaml:"load_fail_per_cpu,omitempty"`
	MemoryWarnPercent float64  `yaml:"memory_warn_percent,omitempty"`
	MemoryFailPercent float64  `yaml:"memory_fail_percent,omitempty"`
	DiskWarnPercent   float64  `yaml:"disk_warn_percent,omitempty"`
	DiskFailPercent   float64  `yaml:"disk_fail_percent,omitempty"`
	InodeWarnPercent  float64  `yaml:"inode_warn_percent,omitempty"`
	InodeFailPercent  float64  `yaml:"inode_fail_percent,omitempty"`
	FilesystemPath    string   `yaml:"filesystem_path,omitempty"`
	RequiredProcesses []string `yaml:"required_processes,omitempty"`
}

type Service struct {
	Name           string        `yaml:"name"`
	Host           string        `yaml:"host,omitempty"`
	Type           string        `yaml:"type"`
	ContainerName  string        `yaml:"container_name"`
	SystemdUnit    string        `yaml:"systemd_unit,omitempty"`
	ProcessName    string        `yaml:"process_name,omitempty"`
	ListenerPort   int           `yaml:"listener_port,omitempty"`
	HealthcheckURL string        `yaml:"healthcheck_url"`
	Checks         ServiceChecks `yaml:"checks,omitempty"`
	SLO            ServiceSLO    `yaml:"slo"`
}

type ServiceChecks struct {
	RestartWarnCount  int           `yaml:"restart_warn_count,omitempty"`
	RestartFailCount  int           `yaml:"restart_fail_count,omitempty"`
	RestartFlapWindow time.Duration `yaml:"restart_flap_window,omitempty"`
	JournalWindow     time.Duration `yaml:"journal_window,omitempty"`
	JournalLines      int           `yaml:"journal_lines,omitempty"`
}

type ServiceSLO struct {
	AvailabilityTarget float64       `yaml:"availability_target"`
	PageShortWindow    time.Duration `yaml:"page_short_window"`
	PageLongWindow     time.Duration `yaml:"page_long_window"`
	PageBurnRate       float64       `yaml:"page_burn_rate"`
	TicketShortWindow  time.Duration `yaml:"ticket_short_window"`
	TicketLongWindow   time.Duration `yaml:"ticket_long_window"`
	TicketBurnRate     float64       `yaml:"ticket_burn_rate"`
	MinSamples         int           `yaml:"min_samples"`
}

func LoadEnvironments(path string) (EnvironmentFile, error) {
	var out EnvironmentFile
	b, err := os.ReadFile(path)
	if err != nil {
		return out, err
	}
	if err := yaml.Unmarshal(b, &out); err != nil {
		return out, err
	}
	if out.Environments == nil {
		out.Environments = map[string]Environment{}
	}
	if err := out.Validate(); err != nil {
		return out, err
	}
	return out, nil
}

func SaveEnvironments(path string, out EnvironmentFile) error {
	if err := out.Validate(); err != nil {
		return err
	}
	b, err := yaml.Marshal(out)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return os.WriteFile(path, b, 0o644)
}

func (f EnvironmentFile) Validate() error {
	for envName, env := range f.Environments {
		if strings.TrimSpace(envName) == "" {
			return fmt.Errorf("environment name must not be empty")
		}
		if project := strings.TrimSpace(env.Project); project != "" {
			if err := validateScopedName("project", project); err != nil {
				return fmt.Errorf("environment %q has invalid project %q: %w", envName, project, err)
			}
		}
		if err := env.Validate(envName); err != nil {
			return err
		}
	}
	return nil
}

func (f EnvironmentFile) Environment(name string) (Environment, bool) {
	env, ok := f.Environments[strings.TrimSpace(name)]
	return env, ok
}

func (f EnvironmentFile) ProjectForEnv(name string) string {
	if env, ok := f.Environment(name); ok {
		return env.ProjectName()
	}
	return "default"
}

func (e Environment) Validate(envName string) error {
	hostNames := map[string]bool{}
	for _, host := range e.Hosts {
		if strings.TrimSpace(host.Name) == "" {
			return fmt.Errorf("environment %q has host with empty name", envName)
		}
		if hostNames[host.Name] {
			return fmt.Errorf("environment %q has duplicate host name %q", envName, host.Name)
		}
		hostNames[host.Name] = true
		if strings.TrimSpace(host.Host) == "" {
			return fmt.Errorf("environment %q host %q must define host", envName, host.Name)
		}
		if host.SSHPort < 0 || host.SSHPort > 65535 {
			return fmt.Errorf("environment %q host %q has invalid ssh_port %d", envName, host.Name, host.SSHPort)
		}
		if err := host.Checks.Validate(envName, host); err != nil {
			return err
		}
	}

	serviceNames := map[string]bool{}
	containerNames := map[string]bool{}
	systemdUnits := map[string]bool{}
	listenerKeys := map[string]bool{}
	for _, svc := range e.Services {
		if strings.TrimSpace(svc.Name) == "" {
			return fmt.Errorf("environment %q has service with empty name", envName)
		}
		if serviceNames[svc.Name] {
			return fmt.Errorf("environment %q has duplicate service name %q", envName, svc.Name)
		}
		serviceNames[svc.Name] = true
		if strings.EqualFold(strings.TrimSpace(svc.Type), "container") && strings.TrimSpace(svc.ContainerName) == "" {
			return fmt.Errorf("environment %q service %q of type container must define container_name", envName, svc.Name)
		}
		if strings.EqualFold(strings.TrimSpace(svc.Type), "systemd") && strings.TrimSpace(svc.SystemdUnit) == "" {
			return fmt.Errorf("environment %q service %q of type systemd must define systemd_unit", envName, svc.Name)
		}
		if strings.EqualFold(strings.TrimSpace(svc.Type), "systemd") && strings.TrimSpace(svc.Host) == "" {
			return fmt.Errorf("environment %q service %q of type systemd must define host", envName, svc.Name)
		}
		if strings.EqualFold(strings.TrimSpace(svc.Type), "listener") && svc.ListenerPort <= 0 {
			return fmt.Errorf("environment %q service %q of type listener must define listener_port", envName, svc.Name)
		}
		if strings.EqualFold(strings.TrimSpace(svc.Type), "listener") && strings.TrimSpace(svc.Host) == "" {
			return fmt.Errorf("environment %q service %q of type listener must define host", envName, svc.Name)
		}
		if svc.ListenerPort < 0 || svc.ListenerPort > 65535 {
			return fmt.Errorf("environment %q service %q has invalid listener_port %d", envName, svc.Name, svc.ListenerPort)
		}
		if ref := strings.TrimSpace(svc.Host); ref != "" && !hostNames[ref] {
			return fmt.Errorf("environment %q service %q references unknown host %q", envName, svc.Name, ref)
		}
		if name := strings.TrimSpace(svc.ContainerName); name != "" {
			if containerNames[name] {
				return fmt.Errorf("environment %q has duplicate container_name %q", envName, name)
			}
			containerNames[name] = true
		}
		if unit := strings.TrimSpace(svc.SystemdUnit); unit != "" {
			if systemdUnits[unit] {
				return fmt.Errorf("environment %q has duplicate systemd_unit %q", envName, unit)
			}
			systemdUnits[unit] = true
		}
		if svc.ListenerPort > 0 && strings.TrimSpace(svc.Host) != "" {
			key := strings.TrimSpace(svc.Host) + ":" + strconv.Itoa(svc.ListenerPort)
			if listenerKeys[key] {
				return fmt.Errorf("environment %q has duplicate listener service on %q", envName, key)
			}
			listenerKeys[key] = true
		}
		if rawURL := strings.TrimSpace(svc.HealthcheckURL); rawURL != "" {
			parsed, err := url.Parse(rawURL)
			if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" {
				return fmt.Errorf("environment %q service %q has invalid healthcheck_url %q", envName, svc.Name, rawURL)
			}
		}
		if err := svc.Checks.Validate(envName, svc); err != nil {
			return err
		}
		if err := svc.SLO.Validate(envName, svc); err != nil {
			return err
		}
	}

	seenDeps := map[string]bool{}
	for _, dep := range e.Dependencies {
		dep = strings.TrimSpace(dep)
		if dep == "" {
			return fmt.Errorf("environment %q has empty dependency entry", envName)
		}
		if seenDeps[dep] {
			return fmt.Errorf("environment %q has duplicate dependency %q", envName, dep)
		}
		seenDeps[dep] = true
		if err := validateDependency(dep); err != nil {
			return fmt.Errorf("environment %q dependency %q invalid: %w", envName, dep, err)
		}
	}

	return nil
}

func (e Environment) ProjectName() string {
	project := strings.TrimSpace(e.Project)
	if project == "" {
		return "default"
	}
	return project
}

func (e Environment) HostByName(name string) (Host, bool) {
	for _, host := range e.Hosts {
		if host.Name == strings.TrimSpace(name) {
			return host, true
		}
	}
	return Host{}, false
}

func (e Environment) HostByEndpoint(endpoint string) (Host, bool) {
	needle := strings.TrimSpace(endpoint)
	for _, host := range e.Hosts {
		if strings.EqualFold(host.Name, needle) || strings.EqualFold(host.Host, needle) {
			return host, true
		}
	}
	return Host{}, false
}

func (s ServiceSLO) Enabled() bool {
	return s.AvailabilityTarget > 0
}

func (s ServiceChecks) WithDefaults(svc Service) ServiceChecks {
	if strings.EqualFold(strings.TrimSpace(svc.Type), "container") {
		if s.RestartWarnCount <= 0 {
			s.RestartWarnCount = 2
		}
		if s.RestartFailCount <= 0 {
			s.RestartFailCount = 5
		}
		if s.RestartFlapWindow <= 0 {
			s.RestartFlapWindow = 15 * time.Minute
		}
	}
	if strings.EqualFold(strings.TrimSpace(svc.Type), "systemd") {
		if s.JournalWindow <= 0 {
			s.JournalWindow = 30 * time.Minute
		}
		if s.JournalLines <= 0 {
			s.JournalLines = 3
		}
	}
	return s
}

func (s ServiceChecks) Validate(envName string, svc Service) error {
	s = s.WithDefaults(svc)
	if strings.EqualFold(strings.TrimSpace(svc.Type), "container") {
		if s.RestartWarnCount <= 0 || s.RestartFailCount <= 0 || s.RestartWarnCount >= s.RestartFailCount {
			return fmt.Errorf("environment %q service %q has invalid restart thresholds", envName, svc.Name)
		}
		if s.RestartFlapWindow <= 0 {
			return fmt.Errorf("environment %q service %q restart_flap_window must be > 0", envName, svc.Name)
		}
	}
	if strings.EqualFold(strings.TrimSpace(svc.Type), "systemd") {
		if s.JournalWindow <= 0 {
			return fmt.Errorf("environment %q service %q journal_window must be > 0", envName, svc.Name)
		}
		if s.JournalLines <= 0 {
			return fmt.Errorf("environment %q service %q journal_lines must be > 0", envName, svc.Name)
		}
	}
	return nil
}

func (h HostChecks) WithDefaults() HostChecks {
	if h.LoadWarnPerCPU <= 0 {
		h.LoadWarnPerCPU = 1.5
	}
	if h.LoadFailPerCPU <= 0 {
		h.LoadFailPerCPU = 2.5
	}
	if h.MemoryWarnPercent <= 0 {
		h.MemoryWarnPercent = 85
	}
	if h.MemoryFailPercent <= 0 {
		h.MemoryFailPercent = 95
	}
	if h.DiskWarnPercent <= 0 {
		h.DiskWarnPercent = 80
	}
	if h.DiskFailPercent <= 0 {
		h.DiskFailPercent = 90
	}
	if h.InodeWarnPercent <= 0 {
		h.InodeWarnPercent = 80
	}
	if h.InodeFailPercent <= 0 {
		h.InodeFailPercent = 90
	}
	if strings.TrimSpace(h.FilesystemPath) == "" {
		h.FilesystemPath = "/"
	}
	return h
}

func (h HostChecks) Validate(envName string, host Host) error {
	h = h.WithDefaults()
	if h.LoadWarnPerCPU <= 0 || h.LoadFailPerCPU <= 0 || h.LoadWarnPerCPU >= h.LoadFailPerCPU {
		return fmt.Errorf("environment %q host %q has invalid load per cpu thresholds", envName, host.Name)
	}
	if err := validatePercentThresholds(envName, host.Name, "memory", h.MemoryWarnPercent, h.MemoryFailPercent); err != nil {
		return err
	}
	if err := validatePercentThresholds(envName, host.Name, "disk", h.DiskWarnPercent, h.DiskFailPercent); err != nil {
		return err
	}
	if err := validatePercentThresholds(envName, host.Name, "inode", h.InodeWarnPercent, h.InodeFailPercent); err != nil {
		return err
	}
	if !strings.HasPrefix(strings.TrimSpace(h.FilesystemPath), "/") {
		return fmt.Errorf("environment %q host %q filesystem_path must be absolute", envName, host.Name)
	}
	seen := map[string]bool{}
	for _, process := range h.RequiredProcesses {
		process = strings.TrimSpace(process)
		if process == "" {
			return fmt.Errorf("environment %q host %q has empty required_processes entry", envName, host.Name)
		}
		if seen[process] {
			return fmt.Errorf("environment %q host %q has duplicate required_processes entry %q", envName, host.Name, process)
		}
		seen[process] = true
	}
	return nil
}

func (s ServiceSLO) WithDefaults() ServiceSLO {
	if !s.Enabled() {
		return s
	}
	if s.PageShortWindow <= 0 {
		s.PageShortWindow = 5 * time.Minute
	}
	if s.PageLongWindow <= 0 {
		s.PageLongWindow = 1 * time.Hour
	}
	if s.PageBurnRate <= 0 {
		s.PageBurnRate = 10
	}
	if s.TicketShortWindow <= 0 {
		s.TicketShortWindow = 30 * time.Minute
	}
	if s.TicketLongWindow <= 0 {
		s.TicketLongWindow = 6 * time.Hour
	}
	if s.TicketBurnRate <= 0 {
		s.TicketBurnRate = 2
	}
	if s.MinSamples <= 0 {
		s.MinSamples = 4
	}
	return s
}

func (s ServiceSLO) Validate(envName string, svc Service) error {
	if !s.Enabled() {
		return nil
	}
	s = s.WithDefaults()
	if strings.TrimSpace(svc.HealthcheckURL) == "" {
		return fmt.Errorf("environment %q service %q enables slo but has no healthcheck_url", envName, svc.Name)
	}
	if s.AvailabilityTarget <= 0 || s.AvailabilityTarget >= 100 {
		return fmt.Errorf("environment %q service %q availability_target must be between 0 and 100", envName, svc.Name)
	}
	if s.PageShortWindow <= 0 || s.PageLongWindow <= 0 || s.PageShortWindow >= s.PageLongWindow {
		return fmt.Errorf("environment %q service %q page windows must be >0 and page_short_window < page_long_window", envName, svc.Name)
	}
	if s.TicketShortWindow <= 0 || s.TicketLongWindow <= 0 || s.TicketShortWindow >= s.TicketLongWindow {
		return fmt.Errorf("environment %q service %q ticket windows must be >0 and ticket_short_window < ticket_long_window", envName, svc.Name)
	}
	if s.PageBurnRate <= 0 || s.TicketBurnRate <= 0 {
		return fmt.Errorf("environment %q service %q burn rates must be >0", envName, svc.Name)
	}
	if s.PageBurnRate < s.TicketBurnRate {
		return fmt.Errorf("environment %q service %q page_burn_rate must be >= ticket_burn_rate", envName, svc.Name)
	}
	if s.MinSamples < 1 {
		return fmt.Errorf("environment %q service %q min_samples must be >= 1", envName, svc.Name)
	}
	return nil
}

func validatePercentThresholds(envName, hostName, label string, warn, fail float64) error {
	if warn <= 0 || fail <= 0 || warn >= fail || warn > 100 || fail > 100 {
		return fmt.Errorf("environment %q host %q has invalid %s percent thresholds", envName, hostName, label)
	}
	return nil
}

func validateScopedName(label, value string) error {
	value = strings.TrimSpace(value)
	if value == "" {
		return fmt.Errorf("%s must not be empty", label)
	}
	for _, r := range value {
		switch {
		case r >= 'a' && r <= 'z':
		case r >= 'A' && r <= 'Z':
		case r >= '0' && r <= '9':
		case r == '-', r == '_', r == '.':
		default:
			return fmt.Errorf("only letters, numbers, '.', '-', and '_' are allowed")
		}
	}
	return nil
}

func ParseDependency(dep string) (scheme, host, port string, err error) {
	raw := strings.TrimSpace(dep)
	switch {
	case strings.HasPrefix(raw, "tcp://"),
		strings.HasPrefix(raw, "redis://"),
		strings.HasPrefix(raw, "mysql://"):
		parsed, parseErr := url.Parse(raw)
		if parseErr != nil {
			return "", "", "", parseErr
		}
		host = strings.TrimSpace(parsed.Hostname())
		port = strings.TrimSpace(parsed.Port())
		if host == "" {
			return "", "", "", fmt.Errorf("missing host")
		}
		scheme = strings.ToLower(strings.TrimSpace(parsed.Scheme))
		switch scheme {
		case "tcp":
			if port == "" {
				return "", "", "", fmt.Errorf("expected host:port")
			}
		case "redis":
			if port == "" {
				port = "6379"
			}
		case "mysql":
			if port == "" {
				port = "3306"
			}
		default:
			return "", "", "", fmt.Errorf("unsupported dependency scheme")
		}
		return scheme, host, port, nil
	case strings.HasPrefix(raw, "http://"), strings.HasPrefix(raw, "https://"):
		parsed, parseErr := url.Parse(raw)
		if parseErr != nil {
			return "", "", "", parseErr
		}
		if parsed.Host == "" {
			return "", "", "", fmt.Errorf("missing host")
		}
		return strings.ToLower(strings.TrimSpace(parsed.Scheme)), strings.TrimSpace(parsed.Hostname()), strings.TrimSpace(parsed.Port()), nil
	default:
		return "", "", "", fmt.Errorf("unsupported dependency scheme")
	}
}

func validateDependency(dep string) error {
	_, host, port, err := ParseDependency(dep)
	if err != nil {
		return err
	}
	if strings.TrimSpace(host) == "" {
		return fmt.Errorf("missing host")
	}
	if strings.HasPrefix(dep, "tcp://") && strings.TrimSpace(port) == "" {
		return fmt.Errorf("expected host:port")
	}
	return nil
}
