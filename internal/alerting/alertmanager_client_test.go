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

func TestAlertmanagerClientExpireSilence(t *testing.T) {
	var gotAuth string
	client := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		gotAuth = r.Header.Get("Authorization")
		if r.Method != http.MethodDelete {
			t.Fatalf("unexpected method %s", r.Method)
		}
		if r.URL.Path != "/api/v2/silence/sil-123" {
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
		return jsonResponse(http.StatusOK, `{}`), nil
	})}

	api := AlertmanagerClient{
		BaseURL:     "http://alertmanager.test",
		BearerToken: "secret",
		HTTPClient:  client,
	}
	if err := api.ExpireSilence(context.Background(), "", "sil-123"); err != nil {
		t.Fatal(err)
	}
	if gotAuth != "Bearer secret" {
		t.Fatalf("unexpected auth header %q", gotAuth)
	}
}

func TestAlertmanagerClientGetSilence(t *testing.T) {
	var gotAuth string
	client := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		gotAuth = r.Header.Get("Authorization")
		if r.Method != http.MethodGet {
			t.Fatalf("unexpected method %s", r.Method)
		}
		if r.URL.Path != "/api/v2/silence/sil-123" {
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
		return jsonResponse(http.StatusOK, `{
			"id":"sil-123",
			"startsAt":"2026-03-20T10:00:00Z",
			"endsAt":"2026-03-20T12:00:00Z",
			"createdBy":"tg:@ops",
			"comment":"acked in telegram",
			"updatedAt":"2026-03-20T10:05:00Z",
			"status":{"state":"active"}
		}`), nil
	})}

	api := AlertmanagerClient{
		BaseURL:     "http://alertmanager.test",
		BearerToken: "secret",
		HTTPClient:  client,
	}
	silence, ok, err := api.GetSilence(context.Background(), "", "sil-123")
	if err != nil {
		t.Fatal(err)
	}
	if !ok || silence.ID != "sil-123" || silence.Status.State != "active" || silence.CreatedBy != "tg:@ops" {
		t.Fatalf("unexpected silence payload: %+v ok=%v", silence, ok)
	}
	if gotAuth != "Bearer secret" {
		t.Fatalf("unexpected auth header %q", gotAuth)
	}
}

func TestAlertmanagerClientGetSilenceNotFound(t *testing.T) {
	client := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		return jsonResponse(http.StatusNotFound, `not found`), nil
	})}

	api := AlertmanagerClient{
		BaseURL:    "http://alertmanager.test",
		HTTPClient: client,
	}
	silence, ok, err := api.GetSilence(context.Background(), "", "missing")
	if err != nil {
		t.Fatal(err)
	}
	if ok || silence.ID != "" {
		t.Fatalf("expected missing silence, got %+v ok=%v", silence, ok)
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
