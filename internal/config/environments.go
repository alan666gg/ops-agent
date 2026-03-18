package config

import (
	"fmt"
	"net"
	"net/url"
	"os"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

type EnvironmentFile struct {
	Environments map[string]Environment `yaml:"environments"`
}

type Environment struct {
	Hosts        []Host    `yaml:"hosts"`
	Services     []Service `yaml:"services"`
	Dependencies []string  `yaml:"dependencies"`
}

type Host struct {
	Name    string `yaml:"name"`
	Host    string `yaml:"host"`
	SSHUser string `yaml:"ssh_user"`
	SSHPort int    `yaml:"ssh_port"`
}

type Service struct {
	Name           string     `yaml:"name"`
	Host           string     `yaml:"host,omitempty"`
	Type           string     `yaml:"type"`
	ContainerName  string     `yaml:"container_name"`
	HealthcheckURL string     `yaml:"healthcheck_url"`
	SLO            ServiceSLO `yaml:"slo"`
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

func (f EnvironmentFile) Validate() error {
	for envName, env := range f.Environments {
		if strings.TrimSpace(envName) == "" {
			return fmt.Errorf("environment name must not be empty")
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
	}

	serviceNames := map[string]bool{}
	containerNames := map[string]bool{}
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
		if ref := strings.TrimSpace(svc.Host); ref != "" && !hostNames[ref] {
			return fmt.Errorf("environment %q service %q references unknown host %q", envName, svc.Name, ref)
		}
		if name := strings.TrimSpace(svc.ContainerName); name != "" {
			if containerNames[name] {
				return fmt.Errorf("environment %q has duplicate container_name %q", envName, name)
			}
			containerNames[name] = true
		}
		if rawURL := strings.TrimSpace(svc.HealthcheckURL); rawURL != "" {
			parsed, err := url.Parse(rawURL)
			if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" {
				return fmt.Errorf("environment %q service %q has invalid healthcheck_url %q", envName, svc.Name, rawURL)
			}
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

func validateDependency(dep string) error {
	switch {
	case strings.HasPrefix(dep, "tcp://"):
		parsed, err := url.Parse(dep)
		if err != nil {
			return err
		}
		if parsed.Host == "" {
			return fmt.Errorf("missing host")
		}
		host, port, err := net.SplitHostPort(parsed.Host)
		if err != nil {
			return fmt.Errorf("expected host:port")
		}
		if strings.TrimSpace(host) == "" || strings.TrimSpace(port) == "" {
			return fmt.Errorf("expected host:port")
		}
		return nil
	case strings.HasPrefix(dep, "http://"), strings.HasPrefix(dep, "https://"):
		parsed, err := url.Parse(dep)
		if err != nil {
			return err
		}
		if parsed.Host == "" {
			return fmt.Errorf("missing host")
		}
		return nil
	default:
		return fmt.Errorf("unsupported dependency scheme")
	}
}
