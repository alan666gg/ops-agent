package notify

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/alan666gg/ops-agent/internal/checks"
	"github.com/alan666gg/ops-agent/internal/incident"
)

func TestWebhookNotifyPostsJSON(t *testing.T) {
	var got incident.Report
	client := &http.Client{
		Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			defer r.Body.Close()
			if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
				t.Fatal(err)
			}
			return &http.Response{
				StatusCode: http.StatusNoContent,
				Body:       io.NopCloser(strings.NewReader("")),
				Header:     make(http.Header),
			}, nil
		}),
	}

	report := incident.Report{Source: "ops-scheduler", Env: "prod", Status: "fail", Summary: "test"}
	if err := (Webhook{URL: "https://example.com/hook", Client: client}).Notify(context.Background(), report); err != nil {
		t.Fatal(err)
	}
	if got.Env != "prod" || got.Status != "fail" {
		t.Fatalf("unexpected report payload: %+v", got)
	}
}

func TestTextMessageIncludesSuggestions(t *testing.T) {
	report := incident.Report{
		Status:  "fail",
		Summary: "ops-scheduler prod: 1 failed",
		Highlights: []string{
			"service_logs_worker [SYSTEMD_RECENT_ERRORS] recent error logs: [2x] panic: database unavailable",
		},
		Suggestions: []incident.Suggestion{
			{Action: "restart_container", Args: []string{"api-1"}, RequiresApproval: true},
		},
		SuppressedChecks: []incident.SuppressedCheck{
			{
				Result:       incidentCheck("service_api"),
				SuppressedBy: "host_ssh_app_1",
				Reason:       "service depends on host app-1 reachability",
			},
		},
	}
	text := TextMessage(report)
	if text == "" {
		t.Fatal("expected non-empty text")
	}
	if want := "restart_container"; !strings.Contains(text, want) {
		t.Fatalf("expected %q in text: %s", want, text)
	}
	if want := "approval_required"; !strings.Contains(text, want) {
		t.Fatalf("expected %q in text: %s", want, text)
	}
	if want := "highlight service_logs_worker [SYSTEMD_RECENT_ERRORS]"; !strings.Contains(text, want) {
		t.Fatalf("expected %q in text: %s", want, text)
	}
	if want := "suppressed service_api by host_ssh_app_1"; !strings.Contains(text, want) {
		t.Fatalf("expected %q in text: %s", want, text)
	}
}

func TestShouldNotify(t *testing.T) {
	if !ShouldNotify("fail", "warn") {
		t.Fatal("expected fail >= warn")
	}
	if ShouldNotify("ok", "warn") {
		t.Fatal("did not expect ok >= warn")
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r)
}

func incidentCheck(name string) checks.Result {
	return checks.Result{Name: name}
}
