package prometheus

import (
	"context"
	"errors"
	"fmt"
	"math"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/alan666gg/ops-agent/internal/config"
)

type SignalObservation struct {
	Name       string  `json:"name"`
	Scope      string  `json:"scope"`
	Strategy   string  `json:"strategy"`
	Subject    string  `json:"subject,omitempty"`
	Comparator string  `json:"comparator"`
	Threshold  float64 `json:"threshold"`
	Value      float64 `json:"value"`
	Summary    string  `json:"summary,omitempty"`
}

var signalPlaceholderPattern = regexp.MustCompile(`\$\{([a-zA-Z0-9_]+)\}`)

func ClientForConfig(cfg config.PrometheusConfig, httpClient *http.Client) (Client, time.Duration, error) {
	return clientForConfigWithEnv(cfg, httpClient, os.LookupEnv)
}

func EvaluateSignals(ctx context.Context, client Client, envName string, env config.Environment, at time.Time) ([]SignalObservation, error) {
	cfg := env.Prometheus.WithDefaults()
	if !cfg.Enabled() || len(cfg.Signals) == 0 {
		return nil, nil
	}

	var observations []SignalObservation
	var errs []error
	for _, signal := range cfg.Signals {
		signal = signal.WithDefaults()
		switch signal.Scope {
		case "env":
			observation, ok, err := evaluateSignal(ctx, client, signal, subjectContext{
				EnvName: envName,
				Project: env.ProjectName(),
				Subject: envName,
			}, at)
			if err != nil {
				errs = append(errs, err)
				continue
			}
			if ok {
				observations = append(observations, observation)
			}
		case "host":
			for _, host := range env.Hosts {
				observation, ok, err := evaluateSignal(ctx, client, signal, subjectContext{
					EnvName: envName,
					Project: env.ProjectName(),
					Host:    &host,
					Subject: host.Name,
				}, at)
				if err != nil {
					errs = append(errs, err)
					continue
				}
				if ok {
					observations = append(observations, observation)
				}
			}
		case "service":
			for _, svc := range env.Services {
				var host *config.Host
				if resolved, ok := env.HostByName(svc.Host); ok {
					host = &resolved
				}
				observation, ok, err := evaluateSignal(ctx, client, signal, subjectContext{
					EnvName: envName,
					Project: env.ProjectName(),
					Host:    host,
					Service: &svc,
					Subject: svc.Name,
				}, at)
				if err != nil {
					errs = append(errs, err)
					continue
				}
				if ok {
					observations = append(observations, observation)
				}
			}
		}
	}
	if len(errs) > 0 {
		return observations, errors.Join(errs...)
	}
	return observations, nil
}

type subjectContext struct {
	EnvName string
	Project string
	Host    *config.Host
	Service *config.Service
	Subject string
}

func evaluateSignal(ctx context.Context, client Client, signal config.PrometheusSignal, subject subjectContext, at time.Time) (SignalObservation, bool, error) {
	query, skipped, err := renderSignalQuery(signal.Query, subject.vars())
	if err != nil {
		return SignalObservation{}, false, fmt.Errorf("prometheus signal %q: %w", signal.Name, err)
	}
	if skipped {
		return SignalObservation{}, false, nil
	}
	resp, err := client.QueryInstant(ctx, query, at)
	if err != nil {
		return SignalObservation{}, false, fmt.Errorf("prometheus signal %q query failed: %w", signal.Name, err)
	}
	value, summary, err := selectSignalValue(resp, signal.Comparator)
	if err != nil {
		return SignalObservation{}, false, fmt.Errorf("prometheus signal %q invalid result: %w", signal.Name, err)
	}
	if !signalTriggered(value, signal.Comparator, signal.Threshold) {
		return SignalObservation{}, false, nil
	}
	return SignalObservation{
		Name:       signal.Name,
		Scope:      signal.Scope,
		Strategy:   signal.Strategy,
		Subject:    subject.Subject,
		Comparator: signal.Comparator,
		Threshold:  signal.Threshold,
		Value:      value,
		Summary:    summary,
	}, true, nil
}

func clientForConfigWithEnv(cfg config.PrometheusConfig, httpClient *http.Client, lookupEnv func(string) (string, bool)) (Client, time.Duration, error) {
	cfg = cfg.WithDefaults()
	if !cfg.Enabled() {
		return Client{}, 0, fmt.Errorf("prometheus not configured for env")
	}
	token := ""
	if name := strings.TrimSpace(cfg.BearerTokenEnv); name != "" {
		value, ok := lookupEnv(name)
		token = strings.TrimSpace(value)
		if !ok || token == "" {
			return Client{}, 0, fmt.Errorf("prometheus bearer token env %q is empty", name)
		}
	}
	if httpClient == nil {
		httpClient = &http.Client{Timeout: cfg.Timeout}
	}
	return Client{
		BaseURL:     cfg.BaseURL,
		BearerToken: token,
		HTTPClient:  httpClient,
	}, cfg.Timeout, nil
}

func (s subjectContext) vars() map[string]string {
	vars := map[string]string{
		"env":     strings.TrimSpace(s.EnvName),
		"project": strings.TrimSpace(s.Project),
	}
	if s.Host != nil {
		vars["host"] = strings.TrimSpace(s.Host.Name)
		vars["host_addr"] = strings.TrimSpace(s.Host.Host)
		vars["ssh_user"] = strings.TrimSpace(s.Host.SSHUser)
		if s.Host.SSHPort > 0 {
			vars["ssh_port"] = strconv.Itoa(s.Host.SSHPort)
		}
	}
	if s.Service != nil {
		vars["service"] = strings.TrimSpace(s.Service.Name)
		vars["service_type"] = strings.TrimSpace(s.Service.Type)
		vars["container"] = strings.TrimSpace(s.Service.ContainerName)
		vars["systemd_unit"] = strings.TrimSpace(s.Service.SystemdUnit)
		vars["process"] = strings.TrimSpace(s.Service.ProcessName)
		if s.Service.ListenerPort > 0 {
			vars["listener_port"] = strconv.Itoa(s.Service.ListenerPort)
		}
	}
	return vars
}

func renderSignalQuery(query string, vars map[string]string) (string, bool, error) {
	matches := signalPlaceholderPattern.FindAllStringSubmatch(query, -1)
	out := query
	for _, match := range matches {
		if len(match) != 2 {
			continue
		}
		key := match[1]
		value, ok := vars[key]
		if !ok {
			return "", false, fmt.Errorf("unknown placeholder %q", key)
		}
		if strings.TrimSpace(value) == "" {
			return "", true, nil
		}
		out = strings.ReplaceAll(out, "${"+key+"}", value)
	}
	return strings.TrimSpace(out), false, nil
}

func selectSignalValue(resp QueryResponse, comparator string) (float64, string, error) {
	switch resp.ResultType {
	case "scalar":
		if resp.Scalar == nil {
			return 0, "", fmt.Errorf("scalar query returned no sample")
		}
		value, err := strconv.ParseFloat(strings.TrimSpace(resp.Scalar.Value), 64)
		if err != nil {
			return 0, "", err
		}
		return value, fmt.Sprintf("scalar=%s", strings.TrimSpace(resp.Scalar.Value)), nil
	case "string":
		if resp.String == nil {
			return 0, "", fmt.Errorf("string query returned no sample")
		}
		value, err := strconv.ParseFloat(strings.TrimSpace(resp.String.Value), 64)
		if err != nil {
			return 0, "", err
		}
		return value, fmt.Sprintf("string=%s", strings.TrimSpace(resp.String.Value)), nil
	case "vector":
		if len(resp.Series) == 0 {
			return 0, "", fmt.Errorf("vector query returned no series")
		}
		return selectFromSeries(resp.Series, comparator, false)
	case "matrix":
		if len(resp.Series) == 0 {
			return 0, "", fmt.Errorf("range query returned no series")
		}
		return selectFromSeries(resp.Series, comparator, true)
	default:
		return 0, "", fmt.Errorf("unsupported result type %q", resp.ResultType)
	}
}

func selectFromSeries(items []Series, comparator string, matrix bool) (float64, string, error) {
	bestValue := 0.0
	bestSummary := ""
	found := false
	for _, item := range items {
		var raw string
		switch {
		case matrix && len(item.Values) > 0:
			raw = item.Values[len(item.Values)-1].Value
		case !matrix && item.Value != nil:
			raw = item.Value.Value
		default:
			continue
		}
		value, err := strconv.ParseFloat(strings.TrimSpace(raw), 64)
		if err != nil {
			return 0, "", err
		}
		if !found {
			bestValue = value
			bestSummary = formatSeriesSummary(item)
			found = true
			continue
		}
		switch strings.ToLower(strings.TrimSpace(comparator)) {
		case "below":
			if value < bestValue {
				bestValue = value
				bestSummary = formatSeriesSummary(item)
			}
		default:
			if value > bestValue {
				bestValue = value
				bestSummary = formatSeriesSummary(item)
			}
		}
	}
	if !found {
		return 0, "", fmt.Errorf("query returned empty series values")
	}
	return bestValue, bestSummary, nil
}

func signalTriggered(value float64, comparator string, threshold float64) bool {
	switch strings.ToLower(strings.TrimSpace(comparator)) {
	case "below":
		return value < threshold
	default:
		return value > threshold
	}
}

func FormatSignalObservation(item SignalObservation) string {
	subject := strings.TrimSpace(item.Subject)
	if subject == "" {
		subject = "(env)"
	}
	return fmt.Sprintf("%s %s %s comparator=%s threshold=%s value=%s%s", item.Name, item.Scope, subject, defaultComparator(item.Comparator), formatSignalNumber(item.Threshold), formatSignalNumber(item.Value), formatSignalSummarySuffix(item.Summary))
}

func formatSignalSummarySuffix(summary string) string {
	if strings.TrimSpace(summary) == "" {
		return ""
	}
	return " top=" + strings.TrimSpace(summary)
}

func formatSignalNumber(v float64) string {
	if math.Abs(v-math.Round(v)) < 0.000001 {
		return strconv.FormatInt(int64(math.Round(v)), 10)
	}
	return strconv.FormatFloat(v, 'f', 3, 64)
}

func defaultComparator(v string) string {
	v = strings.ToLower(strings.TrimSpace(v))
	if v == "" {
		return "above"
	}
	return v
}
