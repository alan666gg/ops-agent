package checks

import (
	"net/url"
	"strconv"
	"strings"

	"github.com/alan666gg/ops-agent/internal/config"
)

func CheckersForEnvironment(env config.Environment) []Checker {
	items := []Checker{HostChecker{}}
	hostsByName := map[string]config.Host{}

	for _, host := range env.Hosts {
		hostsByName[host.Name] = host
		hostChecks := host.Checks.WithDefaults()
		port := host.SSHPort
		if port <= 0 {
			port = 22
		}
		items = append(items, TCPChecker{
			NameLabel: "host_ssh_" + sanitizeName(host.Name),
			Host:      host.Host,
			Port:      strconv.Itoa(port),
		})
		items = append(items, RemoteHostResourceChecker{
			NameLabel: "host_resource_" + sanitizeName(host.Name),
			Host:      host,
			Checks:    hostChecks,
		})
		if len(hostChecks.RequiredProcesses) > 0 {
			items = append(items, RemoteProcessChecker{
				NameLabel: "host_process_" + sanitizeName(host.Name),
				Host:      host,
				Processes: hostChecks.RequiredProcesses,
			})
		}
	}

	for _, svc := range env.Services {
		serviceName := "service_" + sanitizeName(svc.Name)
		serviceChecks := svc.Checks.WithDefaults(svc)
		host, hasHost := hostsByName[strings.TrimSpace(svc.Host)]
		if rawURL := strings.TrimSpace(svc.HealthcheckURL); rawURL != "" {
			items = append(items, HTTPChecker{
				NameLabel: serviceName,
				TargetURL: rawURL,
			})
		} else if hasHost && svc.ListenerPort > 0 {
			items = append(items, TCPChecker{
				NameLabel: serviceName,
				Host:      host.Host,
				Port:      strconv.Itoa(svc.ListenerPort),
			})
		} else if hasHost && strings.EqualFold(strings.TrimSpace(svc.Type), "systemd") && strings.TrimSpace(svc.SystemdUnit) != "" {
			items = append(items, SystemdUnitChecker{
				NameLabel: serviceName,
				Host:      host,
				Unit:      svc.SystemdUnit,
			})
		}
		if hasHost && strings.EqualFold(strings.TrimSpace(svc.Type), "container") && strings.TrimSpace(svc.ContainerName) != "" {
			items = append(items, ContainerRuntimeChecker{
				NameLabel:     "service_runtime_" + sanitizeName(svc.Name),
				Host:          host,
				ContainerName: svc.ContainerName,
				Checks:        serviceChecks,
			})
		}
		if hasHost && strings.EqualFold(strings.TrimSpace(svc.Type), "systemd") && strings.TrimSpace(svc.SystemdUnit) != "" {
			items = append(items, SystemdJournalChecker{
				NameLabel: "service_logs_" + sanitizeName(svc.Name),
				Host:      host,
				Unit:      svc.SystemdUnit,
				Checks:    serviceChecks,
			})
		}
	}

	for _, dep := range env.Dependencies {
		dep = strings.TrimSpace(dep)
		switch {
		case strings.HasPrefix(dep, "tcp://"):
			target := strings.TrimPrefix(dep, "tcp://")
			parts := strings.Split(target, ":")
			if len(parts) == 2 {
				items = append(items, TCPChecker{
					NameLabel: "dependency_tcp_" + sanitizeName(target),
					Host:      parts[0],
					Port:      parts[1],
				})
			}
		case strings.HasPrefix(dep, "http://"), strings.HasPrefix(dep, "https://"):
			items = append(items, HTTPChecker{
				NameLabel: "dependency_http_" + sanitizeName(depLabel(dep)),
				TargetURL: dep,
			})
		}
	}

	return items
}

func depLabel(raw string) string {
	parsed, err := url.Parse(raw)
	if err != nil {
		return raw
	}
	if parsed.Host != "" {
		return parsed.Host + parsed.Path
	}
	return raw
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
