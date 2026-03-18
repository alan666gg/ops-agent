package prometheus

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestClientQueryInstantAndRange(t *testing.T) {
	client := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		switch r.URL.Path {
		case "/api/v1/query":
			if got := r.URL.Query().Get("query"); got != "up" {
				t.Fatalf("unexpected instant query %q", got)
			}
			return jsonResponse(http.StatusOK, `{"status":"success","data":{"resultType":"vector","result":[{"metric":{"job":"api","instance":"app-1:9100"},"value":[1710756000,"1"]}]}}`), nil
		case "/api/v1/query_range":
			if got := r.URL.Query().Get("query"); got != "rate(http_requests_total[5m])" {
				t.Fatalf("unexpected range query %q", got)
			}
			if got := r.URL.Query().Get("step"); got == "" {
				t.Fatal("expected step to be set")
			}
			return jsonResponse(http.StatusOK, `{"status":"success","data":{"resultType":"matrix","result":[{"metric":{"job":"api"},"values":[[1710756000,"12.5"],[1710756060,"15.2"]]}]}}`), nil
		default:
			return jsonResponse(http.StatusNotFound, `{"status":"error","error":"not found"}`), nil
		}
	})}

	api := Client{BaseURL: "http://prometheus.test", HTTPClient: client}
	instant, err := api.QueryInstant(context.Background(), "up", time.Unix(1710756000, 0))
	if err != nil {
		t.Fatal(err)
	}
	if instant.ResultType != "vector" || len(instant.Series) != 1 || instant.Series[0].Value == nil || instant.Series[0].Value.Value != "1" {
		t.Fatalf("unexpected instant response: %+v", instant)
	}
	if !strings.Contains(instant.Summary, "vector query returned 1 series") {
		t.Fatalf("unexpected instant summary: %q", instant.Summary)
	}

	ranged, err := api.QueryRange(context.Background(), "rate(http_requests_total[5m])", time.Unix(1710756000, 0), time.Unix(1710756300, 0), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if ranged.ResultType != "matrix" || len(ranged.Series) != 1 || len(ranged.Series[0].Values) != 2 {
		t.Fatalf("unexpected range response: %+v", ranged)
	}
	if !strings.Contains(ranged.Summary, "range query returned 1 series") {
		t.Fatalf("unexpected range summary: %q", ranged.Summary)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r)
}

func jsonResponse(status int, body string) *http.Response {
	return &http.Response{
		StatusCode: status,
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       io.NopCloser(bytes.NewBufferString(body)),
	}
}

func TestAutoStep(t *testing.T) {
	cases := []struct {
		window time.Duration
		want   time.Duration
	}{
		{10 * time.Minute, 30 * time.Second},
		{90 * time.Minute, 1 * time.Minute},
		{4 * time.Hour, 5 * time.Minute},
		{12 * time.Hour, 15 * time.Minute},
		{48 * time.Hour, 1 * time.Hour},
	}
	for _, tc := range cases {
		if got := AutoStep(tc.window); got != tc.want {
			t.Fatalf("window=%s want %s got %s", tc.window, tc.want, got)
		}
	}
}
