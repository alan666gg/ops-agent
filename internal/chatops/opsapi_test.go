package chatops

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"testing"

	"github.com/alan666gg/ops-agent/internal/approval"
)

func TestOpsAPIClientHealthAndApprove(t *testing.T) {
	var gotAuth string
	var approveBody map[string]any
	client := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		gotAuth = r.Header.Get("Authorization")
		switch r.URL.Path {
		case "/health/run":
			return jsonResponse(http.StatusOK, HealthResponse{Env: "prod", Status: "fail", Summary: "bad"}), nil
		case "/actions/get":
			return jsonResponse(http.StatusOK, approval.Request{ID: "r1", Action: "restart_container", Status: "pending"}), nil
		case "/actions/list":
			return jsonResponse(http.StatusOK, ActionListResponse{Status: "pending", Count: 1, Items: []approval.Request{{ID: "r1", Action: "restart_container", Status: "pending"}}}), nil
		case "/actions/approve":
			if err := json.NewDecoder(r.Body).Decode(&approveBody); err != nil {
				t.Fatal(err)
			}
			return jsonResponse(http.StatusOK, ActionResponse{Status: "executed", Message: "approval processed"}), nil
		default:
			return jsonResponse(http.StatusNotFound, map[string]any{"error": "not found"}), nil
		}
	})}

	api := OpsAPIClient{BaseURL: "http://ops-api.test", Token: "secret", Client: client}
	health, err := api.Health(context.Background(), "prod")
	if err != nil {
		t.Fatal(err)
	}
	if health.Env != "prod" || health.Status != "fail" {
		t.Fatalf("unexpected health response: %+v", health)
	}
	item, err := api.GetAction(context.Background(), "r1")
	if err != nil {
		t.Fatal(err)
	}
	if item.ID != "r1" || item.Action != "restart_container" {
		t.Fatalf("unexpected action response: %+v", item)
	}
	list, err := api.ListActions(context.Background(), "pending", 10, "")
	if err != nil {
		t.Fatal(err)
	}
	if list.Count != 1 || len(list.Items) != 1 || list.Items[0].ID != "r1" {
		t.Fatalf("unexpected list response: %+v", list)
	}

	resp, err := api.Approve(context.Background(), "r1", "tg:@ops", 30)
	if err != nil {
		t.Fatal(err)
	}
	if resp.Status != "executed" {
		t.Fatalf("unexpected approve response: %+v", resp)
	}
	if gotAuth != "Bearer secret" {
		t.Fatalf("missing auth header: %q", gotAuth)
	}
	if approveBody["request_id"] != "r1" || approveBody["approver"] != "tg:@ops" {
		t.Fatalf("unexpected approve body: %+v", approveBody)
	}
}

func TestOpsAPIClientReturnsDecodedErrors(t *testing.T) {
	client := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		return jsonResponse(http.StatusBadRequest, map[string]any{"error": "request is not pending"}), nil
	})}

	api := OpsAPIClient{BaseURL: "http://ops-api.test", Client: client}
	if _, err := api.Approve(context.Background(), "r1", "tg:@ops", 30); err == nil || err.Error() == "" {
		t.Fatal("expected decoded error")
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r)
}

func jsonResponse(status int, payload any) *http.Response {
	b, _ := json.Marshal(payload)
	return &http.Response{
		StatusCode: status,
		Header:     make(http.Header),
		Body:       io.NopCloser(bytes.NewReader(b)),
	}
}
