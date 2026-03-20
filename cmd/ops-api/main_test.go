package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/alan666gg/ops-agent/internal/audit"
	"github.com/alan666gg/ops-agent/internal/incident"
)

func TestResolveAuditFile(t *testing.T) {
	dir := t.TempDir()
	auditDir := filepath.Join(dir, "audit")
	if err := os.MkdirAll(auditDir, 0o755); err != nil {
		t.Fatal(err)
	}
	defaultFile := filepath.Join(auditDir, "api.jsonl")
	if err := os.WriteFile(defaultFile, []byte("{}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(auditDir, "worker.jsonl"), []byte("{}\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	s := &server{auditFile: defaultFile}

	t.Run("default file", func(t *testing.T) {
		got, err := s.resolveAuditFile("")
		if err != nil {
			t.Fatal(err)
		}
		want, err := filepath.EvalSymlinks(defaultFile)
		if err != nil {
			t.Fatal(err)
		}
		if got != want {
			t.Fatalf("expected %s, got %s", want, got)
		}
	})

	t.Run("basename in audit dir", func(t *testing.T) {
		got, err := s.resolveAuditFile("worker.jsonl")
		if err != nil {
			t.Fatal(err)
		}
		want, err := filepath.EvalSymlinks(filepath.Join(auditDir, "worker.jsonl"))
		if err != nil {
			t.Fatal(err)
		}
		if got != want {
			t.Fatalf("unexpected resolved file: %s", got)
		}
	})

	t.Run("reject traversal", func(t *testing.T) {
		if _, err := s.resolveAuditFile("../secrets.txt"); err == nil {
			t.Fatal("expected traversal error")
		}
	})

	t.Run("reject extension", func(t *testing.T) {
		if _, err := s.resolveAuditFile("secrets.txt"); err == nil {
			t.Fatal("expected extension error")
		}
	})
}

func TestResolveTargetHost(t *testing.T) {
	dir := t.TempDir()
	envFile := filepath.Join(dir, "environments.yaml")
	content := `environments:
  prod:
    hosts:
      - name: app-1
        host: 10.0.0.5
        ssh_user: root
        ssh_port: 22
    services: []
    dependencies: []
`
	if err := os.WriteFile(envFile, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	s := &server{envFile: envFile}

	t.Run("empty target host", func(t *testing.T) {
		host, err := s.resolveTargetHost("prod", "")
		if err != nil {
			t.Fatal(err)
		}
		if host != nil {
			t.Fatal("expected nil host")
		}
	})

	t.Run("existing target host", func(t *testing.T) {
		host, err := s.resolveTargetHost("prod", "app-1")
		if err != nil {
			t.Fatal(err)
		}
		if host == nil || host.Host != "10.0.0.5" {
			t.Fatalf("unexpected host: %+v", host)
		}
	})

	t.Run("missing target host", func(t *testing.T) {
		if _, err := s.resolveTargetHost("prod", "missing"); err == nil {
			t.Fatal("expected missing target host error")
		}
	})
}

func TestHandleIncidentTimeline(t *testing.T) {
	now := time.Now().UTC()
	auditFile := filepath.Join(t.TempDir(), "audit.jsonl")
	store := &incident.MemoryStore{}
	record, err := store.SyncReport(incident.Report{
		Source:      "ops-scheduler",
		Project:     "core",
		Env:         "prod",
		Status:      "fail",
		Summary:     "api unhealthy",
		Fingerprint: "fp1",
		FailCount:   1,
	}, now)
	if err != nil {
		t.Fatal(err)
	}
	for _, evt := range []audit.Event{
		{Time: now.Add(-10 * time.Minute), Actor: "tg:@ops", Action: "restart_container", Project: "core", Env: "prod", TargetHost: "app-1", Status: "ok", Message: "manual restart"},
		{Time: now.Add(-5 * time.Minute), Actor: "ops-scheduler", Action: "health_run", Project: "core", Env: "prod", Target: "prod/service_api", Status: "failed", Message: "HTTP_DOWN: connection refused"},
	} {
		if err := audit.AppendJSONL(auditFile, evt); err != nil {
			t.Fatal(err)
		}
	}

	s := &server{
		auditStore:    audit.JSONLStore{Path: auditFile},
		incidentStore: store,
	}
	req := httptest.NewRequest(http.MethodGet, "/incidents/timeline?id="+record.ID+"&minutes=60", nil)
	rr := httptest.NewRecorder()

	s.handleIncidentTimeline(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	var got incident.Timeline
	if err := json.NewDecoder(rr.Body).Decode(&got); err != nil {
		t.Fatal(err)
	}
	if got.Incident.ID != record.ID || got.WindowMinutes != 60 {
		t.Fatalf("unexpected timeline response: %+v", got)
	}
	if len(got.Entries) != 2 {
		t.Fatalf("expected 2 timeline entries, got %+v", got.Entries)
	}
	if len(got.CorrelatedChanges) != 1 || got.CorrelatedChanges[0].Action != "restart_container" {
		t.Fatalf("unexpected correlated changes: %+v", got.CorrelatedChanges)
	}
}

func TestHandleChangeEventAndRecentChanges(t *testing.T) {
	dir := t.TempDir()
	envFile := filepath.Join(dir, "environments.yaml")
	content := `environments:
  prod:
    project: core
    hosts: []
    services: []
    dependencies: []
`
	if err := os.WriteFile(envFile, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	auditFile := filepath.Join(dir, "audit.jsonl")
	s := &server{
		envFile:    envFile,
		auditStore: audit.JSONLStore{Path: auditFile},
	}

	req := httptest.NewRequest(http.MethodPost, "/changes/events", bytes.NewBufferString(`{
		"kind":"deploy",
		"env":"prod",
		"actor":"ci:github-actions",
		"target":"service/api",
		"message":"release 2026.03.20",
		"reference":"git:abc123",
		"url":"https://ci.example/run/1"
	}`))
	rr := httptest.NewRecorder()
	s.handleChangeEvent(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
	var evt audit.Event
	if err := json.NewDecoder(rr.Body).Decode(&evt); err != nil {
		t.Fatal(err)
	}
	if evt.Project != "core" || evt.Env != "prod" || evt.Action != "deploy_event" || evt.Actor != "ci:github-actions" {
		t.Fatalf("unexpected change event response: %+v", evt)
	}
	if !strings.Contains(evt.Message, "ref=git:abc123") || !strings.Contains(evt.Message, "https://ci.example/run/1") {
		t.Fatalf("expected metadata in message, got %q", evt.Message)
	}

	req = httptest.NewRequest(http.MethodGet, "/changes/recent?env=prod&minutes=60&limit=10", nil)
	rr = httptest.NewRecorder()
	s.handleRecentChanges(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
	var resp changesResponse
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatal(err)
	}
	if resp.Count != 1 || len(resp.Items) != 1 {
		t.Fatalf("unexpected changes response: %+v", resp)
	}
	if resp.Items[0].Kind != "change" || resp.Items[0].Action != "deploy_event" || resp.Items[0].Actor != "ci:github-actions" {
		t.Fatalf("unexpected change item: %+v", resp.Items[0])
	}
}

func TestHandlePrometheusQuery(t *testing.T) {
	dir := t.TempDir()
	envFile := filepath.Join(dir, "environments.yaml")
	content := "environments:\n  prod:\n    project: core\n    prometheus:\n      base_url: http://prometheus.test\n      timeout: 5s\n    hosts: []\n    services: []\n    dependencies: []\n"
	if err := os.WriteFile(envFile, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	prevFactory := newPrometheusHTTPClient
	newPrometheusHTTPClient = func(timeout time.Duration) *http.Client {
		return &http.Client{Transport: promRoundTripFunc(func(r *http.Request) (*http.Response, error) {
			if r.URL.Path != "/api/v1/query_range" {
				t.Fatalf("unexpected prometheus path: %s", r.URL.Path)
			}
			if got := r.URL.Query().Get("query"); got != "up" {
				t.Fatalf("unexpected query: %q", got)
			}
			return promJSONResponse(http.StatusOK, `{"status":"success","data":{"resultType":"matrix","result":[{"metric":{"job":"node","instance":"app-1:9100"},"values":[[1710756000,"1"],[1710756060,"1"]]}]}}`), nil
		})}
	}
	defer func() { newPrometheusHTTPClient = prevFactory }()

	s := &server{envFile: envFile}
	req := httptest.NewRequest(http.MethodGet, "/prometheus/query?env=prod&query=up&minutes=30", nil)
	rr := httptest.NewRecorder()

	s.handlePrometheusQuery(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	var got struct {
		Project string `json:"project"`
		Env     string `json:"env"`
		Data    struct {
			ResultType string `json:"result_type"`
			Summary    string `json:"summary"`
			Series     []struct {
				Metric map[string]string `json:"metric"`
			} `json:"series"`
		} `json:"data"`
	}
	if err := json.NewDecoder(rr.Body).Decode(&got); err != nil {
		t.Fatal(err)
	}
	if got.Project != "core" || got.Env != "prod" || got.Data.ResultType != "matrix" || len(got.Data.Series) != 1 {
		t.Fatalf("unexpected prometheus query response: %+v", got)
	}
}

func TestHandleIncidentStatsAndMetrics(t *testing.T) {
	now := time.Now().UTC()
	store := &incident.MemoryStore{}
	rec, err := store.SyncReport(incident.Report{
		Source:      "ops-scheduler",
		Project:     "core",
		Env:         "prod",
		Status:      "fail",
		Summary:     "api unhealthy",
		Fingerprint: "fp-1",
		FailCount:   1,
	}, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Ack(rec.ID, "tg:@ops", "investigating", now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if _, err := store.SyncReport(incident.Report{
		Source:      "ops-scheduler",
		Project:     "core",
		Env:         "prod",
		Status:      "ok",
		Summary:     "api recovered",
		Fingerprint: "fp-ok",
	}, now.Add(5*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if _, err := store.SyncReport(incident.Report{
		Source:      "ops-scheduler",
		Project:     "core",
		Env:         "prod",
		Status:      "fail",
		Summary:     "api unhealthy again",
		Fingerprint: "fp-2",
		FailCount:   1,
	}, now.Add(10*time.Minute)); err != nil {
		t.Fatal(err)
	}
	s := &server{
		incidentStore: store,
		metrics: &apiMetrics{
			requestsTotal:    map[string]int64{},
			errorsTotal:      map[string]int64{},
			durationMsTotal:  map[string]float64{},
			actionsTotal:     map[string]int64{},
			actionsFailTotal: map[string]int64{},
		},
	}

	req := httptest.NewRequest(http.MethodGet, "/incidents/stats?project=core&env=prod", nil)
	rr := httptest.NewRecorder()
	s.handleIncidentStats(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
	var stats incidentStatsResponse
	if err := json.NewDecoder(rr.Body).Decode(&stats); err != nil {
		t.Fatal(err)
	}
	if stats.Summary.OpenRecords != 1 || stats.Summary.ReopenCount != 1 || stats.Summary.AckCount != 1 || stats.Summary.ResolutionCount != 1 {
		t.Fatalf("unexpected incident stats response: %+v", stats)
	}

	mreq := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	mrr := httptest.NewRecorder()
	s.handleMetrics(mrr, mreq)
	body := mrr.Body.String()
	for _, want := range []string{"ops_incident_open_records 1", "ops_incident_reopen_total 1", "ops_incident_resolution_total 1", `ops_incident_scope_open_records{project="core",env="prod",source="ops-scheduler"} 1`} {
		if !strings.Contains(body, want) {
			t.Fatalf("expected %q in metrics body:\n%s", want, body)
		}
	}
}

func TestHandleAlertmanagerWebhook(t *testing.T) {
	dir := t.TempDir()
	envFile := filepath.Join(dir, "environments.yaml")
	content := `environments:
  prod:
    project: core
    hosts: []
    services: []
    dependencies: []
`
	if err := os.WriteFile(envFile, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	auditFile := filepath.Join(dir, "audit.jsonl")
	s := &server{
		envFile:       envFile,
		auditStore:    audit.JSONLStore{Path: auditFile},
		incidentStore: &incident.MemoryStore{},
	}
	body := `{
	  "receiver": "ops-bot",
	  "commonLabels": {"env":"prod","severity":"critical"},
	  "commonAnnotations": {"summary":"API error rate too high"},
	  "alerts": [
	    {"status":"firing","fingerprint":"fp-1","labels":{"alertname":"HighErrorRate","instance":"api-1:9090"},"annotations":{"description":"5xx ratio > 5%"}, "startsAt":"2026-03-18T10:00:00Z"},
	    {"status":"firing","fingerprint":"fp-2","labels":{"alertname":"LatencyHigh","severity":"warning","instance":"api-2:9090"},"annotations":{"summary":"latency p95 > 1s"}, "startsAt":"2026-03-18T10:01:00Z"}
	  ]
	}`
	req := httptest.NewRequest(http.MethodPost, "/alerts/alertmanager", bytes.NewBufferString(body))
	rr := httptest.NewRecorder()

	s.handleAlertmanagerWebhook(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
	var resp alertmanagerIngestResponse
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatal(err)
	}
	if resp.Count != 2 || len(resp.Items) != 2 {
		t.Fatalf("unexpected ingest response: %+v", resp)
	}
	if resp.Items[0].Source != "alertmanager" || resp.Items[0].Project != "core" || !resp.Items[0].Open {
		t.Fatalf("unexpected first item: %+v", resp.Items[0])
	}
	if resp.Items[0].ID == resp.Items[1].ID {
		t.Fatalf("expected distinct ids, got %+v", resp.Items)
	}
	events, err := audit.RecentEvents(auditFile, audit.Query{Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, evt := range events {
		if evt.Action == "alertmanager_receive" {
			count++
		}
	}
	if count != 2 {
		t.Fatalf("unexpected audit events: %+v", events)
	}
}

func TestHandleAckIncidentSyncsAlertmanagerSilence(t *testing.T) {
	now := time.Now().UTC()
	store := &incident.MemoryStore{}
	rec, err := store.SyncReport(incident.Report{
		Source:      "alertmanager",
		Key:         "fp-1",
		Project:     "core",
		Env:         "prod",
		Status:      "fail",
		Summary:     "external alert",
		Fingerprint: "fp-1",
		FailCount:   1,
		External: &incident.ExternalAlert{
			Provider:    "alertmanager",
			ExternalURL: "http://alertmanager.test",
			Labels: map[string]string{
				"alertname": "HighErrorRate",
				"instance":  "api-1:9090",
			},
		},
	}, now)
	if err != nil {
		t.Fatal(err)
	}

	prevFactory := newAlertmanagerHTTPClient
	newAlertmanagerHTTPClient = func(timeout time.Duration) *http.Client {
		return &http.Client{Transport: promRoundTripFunc(func(r *http.Request) (*http.Response, error) {
			if r.URL.Path != "/api/v2/silences" {
				t.Fatalf("unexpected silence path: %s", r.URL.Path)
			}
			if got := r.Header.Get("Authorization"); got != "Bearer api-token" {
				t.Fatalf("unexpected auth header: %q", got)
			}
			return promJSONResponse(http.StatusOK, `{"silenceID":"sil-123"}`), nil
		})}
	}
	defer func() { newAlertmanagerHTTPClient = prevFactory }()

	auditFile := filepath.Join(t.TempDir(), "audit.jsonl")
	s := &server{
		auditStore:    audit.JSONLStore{Path: auditFile},
		incidentStore: store,
		syncAlertAck:  true,
		alertSilence:  2 * time.Hour,
		alertAPIToken: "api-token",
	}
	req := httptest.NewRequest(http.MethodPost, "/incidents/ack", bytes.NewBufferString(`{"id":"`+rec.ID+`","actor":"tg:@ops","note":"investigating"}`))
	rr := httptest.NewRecorder()

	s.handleAckIncident(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
	var got incident.Record
	if err := json.NewDecoder(rr.Body).Decode(&got); err != nil {
		t.Fatal(err)
	}
	if !got.Acknowledged || got.Silence == nil || got.Silence.ID != "sil-123" || !incident.SilenceActive(got.Silence, now.Add(time.Minute)) {
		t.Fatalf("unexpected ack response: %+v", got)
	}
	events, err := audit.RecentEvents(auditFile, audit.Query{Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, evt := range events {
		if evt.Action == "alertmanager_silence" && evt.Status == "ok" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("unexpected audit trail: %+v", events)
	}
}

func TestHandleUnsilenceIncidentExpiresAlertmanagerSilence(t *testing.T) {
	now := time.Now().UTC()
	store := &incident.MemoryStore{}
	rec, err := store.SyncReport(incident.Report{
		Source:      "alertmanager",
		Key:         "fp-1",
		Project:     "core",
		Env:         "prod",
		Status:      "fail",
		Summary:     "external alert",
		Fingerprint: "fp-1",
		FailCount:   1,
		External: &incident.ExternalAlert{
			Provider:    "alertmanager",
			ExternalURL: "http://alertmanager.test",
			Labels:      map[string]string{"alertname": "HighErrorRate"},
		},
	}, now)
	if err != nil {
		t.Fatal(err)
	}
	rec, err = store.SetSilence(rec.ID, incident.ExternalSilence{
		ID:        "sil-123",
		Status:    "active",
		CreatedBy: "tg:@ops",
		StartsAt:  now,
		EndsAt:    now.Add(2 * time.Hour),
	}, now)
	if err != nil {
		t.Fatal(err)
	}

	prevFactory := newAlertmanagerHTTPClient
	newAlertmanagerHTTPClient = func(timeout time.Duration) *http.Client {
		return &http.Client{Transport: promRoundTripFunc(func(r *http.Request) (*http.Response, error) {
			if r.Method != http.MethodDelete {
				t.Fatalf("unexpected method: %s", r.Method)
			}
			if r.URL.Path != "/api/v2/silence/sil-123" {
				t.Fatalf("unexpected unsilence path: %s", r.URL.Path)
			}
			if got := r.Header.Get("Authorization"); got != "Bearer api-token" {
				t.Fatalf("unexpected auth header: %q", got)
			}
			return promJSONResponse(http.StatusOK, `{}`), nil
		})}
	}
	defer func() { newAlertmanagerHTTPClient = prevFactory }()

	auditFile := filepath.Join(t.TempDir(), "audit.jsonl")
	s := &server{
		auditStore:    audit.JSONLStore{Path: auditFile},
		incidentStore: store,
		alertAPIToken: "api-token",
	}
	req := httptest.NewRequest(http.MethodPost, "/incidents/unsilence", bytes.NewBufferString(`{"id":"`+rec.ID+`","actor":"tg:@ops","note":"resume notifications"}`))
	rr := httptest.NewRecorder()

	s.handleUnsilenceIncident(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
	var got incident.Record
	if err := json.NewDecoder(rr.Body).Decode(&got); err != nil {
		t.Fatal(err)
	}
	if got.Silence == nil || incident.SilenceActive(got.Silence, now.Add(time.Minute)) || got.Silence.ExpiredBy != "tg:@ops" {
		t.Fatalf("unexpected unsilence response: %+v", got)
	}
	events, err := audit.RecentEvents(auditFile, audit.Query{Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if len(events) == 0 || events[0].Action != "alertmanager_unsilence" || events[0].Status != "ok" {
		t.Fatalf("unexpected unsilence audit trail: %+v", events)
	}
}

func TestHandleReconcileAlertmanagerRefreshesExpiredSilence(t *testing.T) {
	now := time.Now().UTC()
	store := &incident.MemoryStore{}
	rec, err := store.SyncReport(incident.Report{
		Source:      "alertmanager",
		Key:         "fp-1",
		Project:     "core",
		Env:         "prod",
		Status:      "fail",
		Summary:     "external alert",
		Fingerprint: "fp-1",
		FailCount:   1,
		External: &incident.ExternalAlert{
			Provider:    "alertmanager",
			ExternalURL: "http://alertmanager.test",
			Labels:      map[string]string{"alertname": "HighErrorRate"},
		},
	}, now)
	if err != nil {
		t.Fatal(err)
	}
	_, err = store.SetSilence(rec.ID, incident.ExternalSilence{
		ID:        "sil-123",
		Status:    "active",
		CreatedBy: "tg:@ops",
		Comment:   "acked",
		StartsAt:  now.Add(-30 * time.Minute),
		EndsAt:    now.Add(2 * time.Hour),
		UpdatedAt: now,
	}, now)
	if err != nil {
		t.Fatal(err)
	}

	prevFactory := newAlertmanagerHTTPClient
	newAlertmanagerHTTPClient = func(timeout time.Duration) *http.Client {
		return &http.Client{Transport: promRoundTripFunc(func(r *http.Request) (*http.Response, error) {
			if r.Method != http.MethodGet {
				t.Fatalf("unexpected method: %s", r.Method)
			}
			if r.URL.Path != "/api/v2/silence/sil-123" {
				t.Fatalf("unexpected reconcile path: %s", r.URL.Path)
			}
			if got := r.Header.Get("Authorization"); got != "Bearer api-token" {
				t.Fatalf("unexpected auth header: %q", got)
			}
			return promJSONResponse(http.StatusNotFound, `not found`), nil
		})}
	}
	defer func() { newAlertmanagerHTTPClient = prevFactory }()

	auditFile := filepath.Join(t.TempDir(), "audit.jsonl")
	s := &server{
		auditStore:    audit.JSONLStore{Path: auditFile},
		incidentStore: store,
		alertAPIToken: "api-token",
		alertTimeout:  5 * time.Second,
	}

	req := httptest.NewRequest(http.MethodPost, "/incidents/reconcile-alertmanager", bytes.NewBufferString(`{"id":"`+rec.ID+`","actor":"tg:@ops"}`))
	rr := httptest.NewRecorder()

	s.handleReconcileAlertmanager(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
	var resp alertmanagerReconcileResponse
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatal(err)
	}
	if resp.Checked != 1 || resp.Updated != 1 || resp.Expired != 1 || resp.Failed != 0 {
		t.Fatalf("unexpected reconcile response: %+v", resp)
	}
	item, ok, err := store.Get(rec.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !ok || item.Silence == nil || incident.SilenceStatus(item.Silence, now) != "expired" || item.Silence.ExpiredBy != "alertmanager" {
		t.Fatalf("unexpected reconciled incident: %+v", item)
	}
	events, err := audit.RecentEvents(auditFile, audit.Query{Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, evt := range events {
		if evt.Action == "alertmanager_reconcile" && evt.Status == "expired" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("unexpected reconcile audit trail: %+v", events)
	}
}

type promRoundTripFunc func(*http.Request) (*http.Response, error)

func (f promRoundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r)
}

func promJSONResponse(status int, body string) *http.Response {
	return &http.Response{
		StatusCode: status,
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       io.NopCloser(strings.NewReader(body)),
	}
}
