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
		port := host.SSHPort
		if port <= 0 {
			port = 22
		}
		items = append(items, TCPChecker{
			NameLabel: "host_ssh_" + sanitizeName(host.Name),
			Host:      host.Host,
			Port:      strconv.Itoa(port),
		})
	}

	for _, svc := range env.Services {
		if rawURL := strings.TrimSpace(svc.HealthcheckURL); rawURL != "" {
			items = append(items, HTTPChecker{
				NameLabel: "service_" + sanitizeName(svc.Name),
				TargetURL: rawURL,
			})
			continue
		}
		host, ok := hostsByName[strings.TrimSpace(svc.Host)]
		if !ok {
			continue
		}
		if svc.ListenerPort > 0 {
			items = append(items, TCPChecker{
				NameLabel: "service_" + sanitizeName(svc.Name),
				Host:      host.Host,
				Port:      strconv.Itoa(svc.ListenerPort),
			})
			continue
		}
		if strings.EqualFold(strings.TrimSpace(svc.Type), "systemd") && strings.TrimSpace(svc.SystemdUnit) != "" {
			items = append(items, SystemdUnitChecker{
				NameLabel: "service_" + sanitizeName(svc.Name),
				Host:      host,
				Unit:      svc.SystemdUnit,
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
