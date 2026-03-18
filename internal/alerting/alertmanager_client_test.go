package alerting

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/alan666gg/ops-agent/internal/incident"
)

func TestAlertmanagerClientCreateSilence(t *testing.T) {
	var gotAuth string
	client := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		gotAuth = r.Header.Get("Authorization")
		if r.URL.Path != "/api/v2/silences" {
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Contains(body, []byte(`"alertname"`)) || !bytes.Contains(body, []byte(`"HighErrorRate"`)) {
			t.Fatalf("unexpected silence body: %s", string(body))
		}
		return jsonResponse(http.StatusOK, `{"silenceID":"sil-123"}`), nil
	})}

	api := AlertmanagerClient{
		BaseURL:     "http://alertmanager.test",
		BearerToken: "secret",
		HTTPClient:  client,
	}
	id, err := api.CreateSilence(context.Background(), &incident.ExternalAlert{
		Provider:    "alertmanager",
		ExternalURL: "http://alertmanager.test",
		Labels: map[string]string{
			"alertname": "HighErrorRate",
			"instance":  "api-1:9090",
		},
	}, 2*time.Hour, "tg:@ops", "acked in telegram")
	if err != nil {
		t.Fatal(err)
	}
	if id != "sil-123" || gotAuth != "Bearer secret" {
		t.Fatalf("unexpected silence result id=%q auth=%q", id, gotAuth)
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
