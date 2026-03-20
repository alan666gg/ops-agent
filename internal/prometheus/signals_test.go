package prometheus

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/alan666gg/ops-agent/internal/config"
)

func TestClientForConfigReadsBearerTokenEnv(t *testing.T) {
	cfg := config.PrometheusConfig{
		BaseURL:        "http://prometheus.test",
		BearerTokenEnv: "PROM_TOKEN",
		Timeout:        3 * time.Second,
	}
	client, timeout, err := clientForConfigWithEnv(cfg, nil, func(key string) (string, bool) {
		if key != "PROM_TOKEN" {
			t.Fatalf("unexpected env lookup %q", key)
		}
		return "secret-token", true
	})
	if err != nil {
		t.Fatal(err)
	}
	if client.BearerToken != "secret-token" || timeout != 3*time.Second {
		t.Fatalf("unexpected client config: %+v timeout=%s", client, timeout)
	}
}

func TestEvaluateSignalsUsesScopedTemplatesAndStrategies(t *testing.T) {
	httpClient := &http.Client{Transport: signalRoundTripFunc(func(r *http.Request) (*http.Response, error) {
		switch r.URL.Path {
		case "/api/v1/query":
			query := r.URL.Query().Get("query")
			switch query {
			case `sum(rate(http_requests_errors_total{env="prod"}[5m]))`:
				return signalJSONResponse(http.StatusOK, `{"status":"success","data":{"resultType":"scalar","result":[1710756000,"0.18"]}}`), nil
			case `node_load1{instance="10.0.0.5:9100"}`:
				return signalJSONResponse(http.StatusOK, `{"status":"success","data":{"resultType":"vector","result":[{"metric":{"instance":"10.0.0.5:9100"},"value":[1710756000,"2.7"]}]}}`), nil
			case `container_memory_working_set_bytes{name="api-1"}`:
				return signalJSONResponse(http.StatusOK, `{"status":"success","data":{"resultType":"vector","result":[{"metric":{"name":"api-1"},"value":[1710756000,"123"]}]}}`), nil
			default:
				t.Fatalf("unexpected signal query %q", query)
			}
		default:
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
		return nil, nil
	})}
	client := Client{BaseURL: "http://prometheus.test", HTTPClient: httpClient}
	env := config.Environment{
		Project: "core",
		Prometheus: config.PrometheusConfig{
			BaseURL: "http://prometheus.test",
			Signals: []config.PrometheusSignal{
				{Name: "env_error_rate", Scope: "env", Strategy: "change_regression", Query: `sum(rate(http_requests_errors_total{env="${env}"}[5m]))`, Comparator: "above", Threshold: 0.05},
				{Name: "host_cpu_hot", Scope: "host", Strategy: "capacity", Query: `node_load1{instance="${host_addr}:9100"}`, Comparator: "above", Threshold: 2},
				{Name: "service_mem_hot", Scope: "service", Strategy: "capacity", Query: `container_memory_working_set_bytes{name="${container}"}`, Comparator: "above", Threshold: 100},
			},
		},
		Hosts:    []config.Host{{Name: "app-1", Host: "10.0.0.5"}},
		Services: []config.Service{{Name: "api", Host: "app-1", Type: "container", ContainerName: "api-1"}},
	}

	got, err := EvaluateSignals(context.Background(), client, "prod", env, time.Unix(1710756000, 0))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 {
		t.Fatalf("expected 3 signal observations, got %+v", got)
	}
	if got[0].Name != "env_error_rate" || got[0].Strategy != "change_regression" || got[0].Subject != "prod" {
		t.Fatalf("unexpected env signal: %+v", got[0])
	}
	if got[1].Name != "host_cpu_hot" || got[1].Strategy != "capacity" || got[1].Subject != "app-1" {
		t.Fatalf("unexpected host signal: %+v", got[1])
	}
	if got[2].Name != "service_mem_hot" || got[2].Strategy != "capacity" || got[2].Subject != "api" {
		t.Fatalf("unexpected service signal: %+v", got[2])
	}
}

func TestEvaluateSignalsSkipsMissingTemplateSubjects(t *testing.T) {
	httpClient := &http.Client{Transport: signalRoundTripFunc(func(r *http.Request) (*http.Response, error) {
		t.Fatalf("did not expect prometheus query for skipped service template: %s", r.URL.String())
		return nil, nil
	})}
	client := Client{BaseURL: "http://prometheus.test", HTTPClient: httpClient}
	env := config.Environment{
		Project: "core",
		Prometheus: config.PrometheusConfig{
			BaseURL: "http://prometheus.test",
			Signals: []config.PrometheusSignal{
				{Name: "systemd_errors", Scope: "service", Strategy: "investigate", Query: `sum(rate(service_errors_total{unit="${systemd_unit}"}[5m]))`, Comparator: "above", Threshold: 0},
			},
		},
		Services: []config.Service{{Name: "api", Type: "container", ContainerName: "api-1"}},
	}

	got, err := EvaluateSignals(context.Background(), client, "prod", env, time.Unix(1710756000, 0))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Fatalf("expected skipped service signal, got %+v", got)
	}
}

func TestSelectSignalValueUsesComparatorDirection(t *testing.T) {
	resp := QueryResponse{
		ResultType: "vector",
		Series: []Series{
			{Metric: map[string]string{"instance": "a"}, Value: &Sample{Value: "3"}},
			{Metric: map[string]string{"instance": "b"}, Value: &Sample{Value: "1"}},
		},
	}
	value, summary, err := selectSignalValue(resp, "below")
	if err != nil {
		t.Fatal(err)
	}
	if value != 1 || !strings.Contains(summary, "instance=b=1") {
		t.Fatalf("unexpected selected value/summary: value=%v summary=%q", value, summary)
	}
}

type signalRoundTripFunc func(*http.Request) (*http.Response, error)

func (f signalRoundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r)
}

func signalJSONResponse(status int, body string) *http.Response {
	return &http.Response{
		StatusCode: status,
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       io.NopCloser(bytes.NewBufferString(body)),
		Request:    &http.Request{URL: &url.URL{}},
	}
}
