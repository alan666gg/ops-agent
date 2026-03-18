package discovery

import (
	"context"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/alan666gg/ops-agent/internal/config"
)

type URLProber interface {
	FirstReachable(ctx context.Context, urls []string, timeout time.Duration) string
}

type HTTPProber struct {
	Client *http.Client
}

type ApplyOptions struct {
	HealthPaths  []string
	ProbeTimeout time.Duration
	Prober       URLProber
}

type ApplyResult struct {
	Added   []config.Service `json:"added" yaml:"added"`
	Updated []config.Service `json:"updated" yaml:"updated"`
	Skipped []string         `json:"skipped,omitempty" yaml:"skipped,omitempty"`
}

func DefaultHealthPaths() []string {
	return []string{"/healthz", "/health", "/"}
}

func (p HTTPProber) FirstReachable(ctx context.Context, urls []string, timeout time.Duration) string {
	if len(urls) == 0 {
		return ""
	}
	client := p.Client
	if client == nil {
		client = &http.Client{Timeout: timeout}
	}
	for _, rawURL := range urls {
		reqCtx, cancel := context.WithTimeout(ctx, timeout)
		req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, rawURL, nil)
		if err != nil {
			cancel()
			continue
		}
		resp, err := client.Do(req)
		cancel()
		if err != nil {
			continue
		}
		_ = resp.Body.Close()
		if resp.StatusCode < 500 {
			return rawURL
		}
	}
	return ""
}

func ApplyReport(ctx context.Context, env *config.Environment, report Report, opts ApplyOptions) ApplyResult {
	if env == nil {
		return ApplyResult{Skipped: []string{"environment is nil"}}
	}
	healthPaths := normalizeHealthPaths(opts.HealthPaths)
	prober := opts.Prober
	if prober == nil {
		prober = HTTPProber{}
	}
	if opts.ProbeTimeout <= 0 {
		opts.ProbeTimeout = 1500 * time.Millisecond
	}

	serviceNames := map[string]bool{}
	for _, svc := range env.Services {
		serviceNames[svc.Name] = true
	}
	var result ApplyResult
	for _, candidate := range report.SuggestedService {
		idx := findService(env.Services, candidate)
		urls := candidateURLsForApply(report.HostAddress, candidate, healthPaths)
		reachable := prober.FirstReachable(ctx, urls, opts.ProbeTimeout)
		if idx >= 0 {
			current := env.Services[idx]
			updated := false
			if strings.TrimSpace(current.HealthcheckURL) == "" && reachable != "" {
				current.HealthcheckURL = reachable
				updated = true
			}
			if strings.TrimSpace(current.Host) == "" && candidate.Host != "" {
				current.Host = candidate.Host
				updated = true
			}
			if strings.TrimSpace(current.Type) == "" && strings.TrimSpace(candidate.Type) != "" {
				current.Type = candidate.Type
				updated = true
			}
			if strings.TrimSpace(current.ContainerName) == "" && strings.TrimSpace(candidate.ContainerName) != "" {
				current.ContainerName = candidate.ContainerName
				updated = true
			}
			if strings.TrimSpace(current.SystemdUnit) == "" && strings.TrimSpace(candidate.SystemdUnit) != "" {
				current.SystemdUnit = candidate.SystemdUnit
				updated = true
			}
			if strings.TrimSpace(current.ProcessName) == "" && strings.TrimSpace(candidate.ProcessName) != "" {
				current.ProcessName = candidate.ProcessName
				updated = true
			}
			if current.ListenerPort <= 0 && candidate.ListenerPort > 0 {
				current.ListenerPort = candidate.ListenerPort
				updated = true
			}
			if updated {
				env.Services[idx] = current
				result.Updated = append(result.Updated, current)
			} else {
				result.Skipped = append(result.Skipped, candidateID(candidate))
			}
			continue
		}
		if reachable == "" && candidate.ListenerPort <= 0 && strings.TrimSpace(candidate.SystemdUnit) == "" {
			result.Skipped = append(result.Skipped, candidateID(candidate))
			continue
		}

		name := uniqueServiceName(serviceNames, candidate.Name)
		serviceNames[name] = true
		item := config.Service{
			Name:           name,
			Host:           candidate.Host,
			Type:           candidate.Type,
			ContainerName:  candidate.ContainerName,
			SystemdUnit:    candidate.SystemdUnit,
			ProcessName:    candidate.ProcessName,
			ListenerPort:   candidate.ListenerPort,
			HealthcheckURL: reachable,
		}
		env.Services = append(env.Services, item)
		result.Added = append(result.Added, item)
	}
	sort.Slice(env.Services, func(i, j int) bool { return env.Services[i].Name < env.Services[j].Name })
	return result
}

func candidateURLsForApply(hostAddress string, candidate ServiceCandidate, healthPaths []string) []string {
	var out []string
	seen := map[string]bool{}
	for _, base := range candidate.CandidateHealthURLs {
		base = strings.TrimRight(strings.TrimSpace(base), "/")
		if base == "" {
			continue
		}
		for _, path := range healthPaths {
			u := base + normalizePath(path)
			if !seen[u] {
				seen[u] = true
				out = append(out, u)
			}
		}
	}
	if len(out) == 0 && strings.TrimSpace(hostAddress) != "" && candidate.ListenerPort > 0 {
		for _, scheme := range schemesForPort(candidate.ListenerPort) {
			base := scheme + "://" + strings.TrimSpace(hostAddress) + ":" + strconv.Itoa(candidate.ListenerPort)
			for _, path := range healthPaths {
				u := base + normalizePath(path)
				if !seen[u] {
					seen[u] = true
					out = append(out, u)
				}
			}
		}
	}
	if len(out) == 0 && strings.TrimSpace(hostAddress) != "" && candidate.ListenerPort <= 0 {
		for _, path := range healthPaths {
			u := "http://" + strings.TrimSpace(hostAddress) + normalizePath(path)
			if !seen[u] {
				seen[u] = true
				out = append(out, u)
			}
		}
	}
	return out
}

func normalizeHealthPaths(paths []string) []string {
	if len(paths) == 0 {
		return DefaultHealthPaths()
	}
	var out []string
	for _, path := range paths {
		path = normalizePath(path)
		if path != "" {
			out = append(out, path)
		}
	}
	if len(out) == 0 {
		return DefaultHealthPaths()
	}
	return out
}

func normalizePath(path string) string {
	path = strings.TrimSpace(path)
	if path == "" {
		return ""
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	return path
}

func findService(items []config.Service, candidate ServiceCandidate) int {
	for i, item := range items {
		if strings.TrimSpace(item.ContainerName) != "" && item.ContainerName == candidate.ContainerName {
			return i
		}
		if strings.TrimSpace(item.SystemdUnit) != "" && item.SystemdUnit == candidate.SystemdUnit {
			return i
		}
		if item.ListenerPort > 0 && candidate.ListenerPort > 0 && item.Host == candidate.Host && item.ListenerPort == candidate.ListenerPort {
			return i
		}
		if strings.TrimSpace(item.ContainerName) == "" && item.Host == candidate.Host && item.Name == candidate.Name {
			return i
		}
	}
	return -1
}

func candidateID(candidate ServiceCandidate) string {
	switch {
	case strings.TrimSpace(candidate.ContainerName) != "":
		return candidate.ContainerName
	case strings.TrimSpace(candidate.SystemdUnit) != "":
		return candidate.SystemdUnit
	case candidate.ListenerPort > 0:
		return candidate.Name + ":" + strconv.Itoa(candidate.ListenerPort)
	default:
		return candidate.Name
	}
}

func uniqueServiceName(seen map[string]bool, base string) string {
	base = sanitizeName(base)
	if base == "" {
		base = "service"
	}
	if !seen[base] {
		return base
	}
	for i := 2; ; i++ {
		name := base + "-" + strconv.Itoa(i)
		if !seen[name] {
			return name
		}
	}
}
