package chatops

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/alan666gg/ops-agent/internal/approval"
	"github.com/alan666gg/ops-agent/internal/incident"
	promapi "github.com/alan666gg/ops-agent/internal/prometheus"
)

func TestOpsAPIClientHealthAndApprove(t *testing.T) {
	var gotAuth string
	var approveBody map[string]any
	client := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		gotAuth = r.Header.Get("Authorization")
		switch r.URL.Path {
		case "/health/run":
			return jsonResponse(http.StatusOK, HealthResponse{Env: "prod", Status: "fail", Summary: "bad"}), nil
		case "/prometheus/query":
			return jsonResponse(http.StatusOK, PrometheusQueryResponse{
				Project: "core",
				Env:     "prod",
				Data:    promapi.QueryResponse{Query: "up", ResultType: "vector", Summary: "vector query returned 1 series"},
			}), nil
		case "/changes/recent":
			return jsonResponse(http.StatusOK, RecentChangesResponse{
				WindowMinutes: 120,
				Projects:      []string{"core"},
				Env:           "prod",
				Count:         1,
				Items: []incident.TimelineEntry{
					{Kind: "change", Action: "deploy_release", Status: "ok", Actor: "ci:github-actions", Target: "service/api"},
				},
			}), nil
		case "/incidents/active":
			return jsonResponse(http.StatusOK, IncidentListResponse{Count: 1, Items: []incident.Record{{ID: "ops-scheduler|core|prod", Project: "core", Env: "prod", Status: "fail"}}}), nil
		case "/incidents/get":
			return jsonResponse(http.StatusOK, incident.Record{ID: "ops-scheduler|core|prod", Project: "core", Env: "prod", Status: "fail"}), nil
		case "/incidents/timeline":
			return jsonResponse(http.StatusOK, IncidentTimelineResponse{
				Incident:      incident.Record{ID: "ops-scheduler|core|prod", Project: "core", Env: "prod", Status: "fail"},
				WindowMinutes: 90,
				Entries:       []incident.TimelineEntry{{Kind: "signal", Action: "health_run", Status: "failed"}},
			}), nil
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
	prom, err := api.PrometheusQuery(context.Background(), "prod", "up", 30, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if prom.Project != "core" || prom.Data.Query != "up" {
		t.Fatalf("unexpected prometheus response: %+v", prom)
	}
	changes, err := api.RecentChanges(context.Background(), 120, "prod", []string{"core"}, 5)
	if err != nil {
		t.Fatal(err)
	}
	if changes.Count != 1 || len(changes.Items) != 1 || changes.Items[0].Action != "deploy_release" {
		t.Fatalf("unexpected changes response: %+v", changes)
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
	incidents, err := api.ActiveIncidents(context.Background(), 10, "prod", []string{"core"})
	if err != nil {
		t.Fatal(err)
	}
	if incidents.Count != 1 || len(incidents.Items) != 1 || incidents.Items[0].Project != "core" {
		t.Fatalf("unexpected incident list response: %+v", incidents)
	}
	incidentItem, err := api.GetIncident(context.Background(), "ops-scheduler|core|prod")
	if err != nil {
		t.Fatal(err)
	}
	if incidentItem.ID == "" || incidentItem.Project != "core" {
		t.Fatalf("unexpected incident detail response: %+v", incidentItem)
	}
	timeline, err := api.GetIncidentTimeline(context.Background(), "ops-scheduler|core|prod", 90)
	if err != nil {
		t.Fatal(err)
	}
	if timeline.WindowMinutes != 90 || timeline.Incident.Project != "core" || len(timeline.Entries) != 1 {
		t.Fatalf("unexpected incident timeline response: %+v", timeline)
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
