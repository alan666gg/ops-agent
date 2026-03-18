package chatops

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/alan666gg/ops-agent/internal/approval"
	"github.com/alan666gg/ops-agent/internal/checks"
	"github.com/alan666gg/ops-agent/internal/incident"
)

type OpsAPIClient struct {
	BaseURL string
	Token   string
	Client  *http.Client
}

type HealthResponse struct {
	Env              string                     `json:"env"`
	Status           string                     `json:"status"`
	Results          []checks.Result            `json:"results"`
	SuppressedChecks []incident.SuppressedCheck `json:"suppressed_checks"`
	Suggestions      []incident.Suggestion      `json:"suggestions"`
	Summary          string                     `json:"summary"`
}

type IncidentSummary struct {
	WindowMinutes int            `json:"window_minutes"`
	Total         int            `json:"total_events"`
	ByStatus      map[string]int `json:"by_status"`
	TopTargets    []string       `json:"top_targets"`
}

type PendingResponse struct {
	Count int                `json:"count"`
	Items []approval.Request `json:"items"`
}

type ActionListResponse struct {
	Status     string             `json:"status"`
	Count      int                `json:"count"`
	Items      []approval.Request `json:"items"`
	NextCursor string             `json:"next_cursor,omitempty"`
}

type RequestActionRequest struct {
	Action     string   `json:"action"`
	Env        string   `json:"env,omitempty"`
	TargetHost string   `json:"target_host,omitempty"`
	Args       []string `json:"args,omitempty"`
	Actor      string   `json:"actor"`
}

type RequestActionResponse struct {
	Status    string `json:"status"`
	Message   string `json:"message"`
	RequestID string `json:"request_id,omitempty"`
}

type ActionResponse struct {
	Status   string `json:"status"`
	Message  string `json:"message"`
	ExitCode int    `json:"exit_code,omitempty"`
	Output   string `json:"output,omitempty"`
}

func (c OpsAPIClient) Health(ctx context.Context, env string) (HealthResponse, error) {
	var out HealthResponse
	q := url.Values{}
	q.Set("env", strings.TrimSpace(env))
	if err := c.doJSON(ctx, http.MethodGet, "/health/run?"+q.Encode(), nil, &out); err != nil {
		return out, err
	}
	return out, nil
}

func (c OpsAPIClient) IncidentSummary(ctx context.Context, minutes int) (IncidentSummary, error) {
	var out IncidentSummary
	q := url.Values{}
	q.Set("minutes", fmt.Sprintf("%d", minutes))
	if err := c.doJSON(ctx, http.MethodGet, "/incidents/summary?"+q.Encode(), nil, &out); err != nil {
		return out, err
	}
	return out, nil
}

func (c OpsAPIClient) Pending(ctx context.Context, limit int) (PendingResponse, error) {
	var out PendingResponse
	q := url.Values{}
	q.Set("limit", fmt.Sprintf("%d", limit))
	if err := c.doJSON(ctx, http.MethodGet, "/actions/pending?"+q.Encode(), nil, &out); err != nil {
		return out, err
	}
	return out, nil
}

func (c OpsAPIClient) GetAction(ctx context.Context, id string) (approval.Request, error) {
	var out approval.Request
	q := url.Values{}
	q.Set("id", strings.TrimSpace(id))
	if err := c.doJSON(ctx, http.MethodGet, "/actions/get?"+q.Encode(), nil, &out); err != nil {
		return out, err
	}
	return out, nil
}

func (c OpsAPIClient) ListActions(ctx context.Context, status string, limit int, cursor string) (ActionListResponse, error) {
	var out ActionListResponse
	q := url.Values{}
	q.Set("status", strings.TrimSpace(status))
	q.Set("limit", fmt.Sprintf("%d", limit))
	if strings.TrimSpace(cursor) != "" {
		q.Set("cursor", strings.TrimSpace(cursor))
	}
	if err := c.doJSON(ctx, http.MethodGet, "/actions/list?"+q.Encode(), nil, &out); err != nil {
		return out, err
	}
	return out, nil
}

func (c OpsAPIClient) RequestAction(ctx context.Context, req RequestActionRequest) (RequestActionResponse, error) {
	var out RequestActionResponse
	if err := c.doJSON(ctx, http.MethodPost, "/actions/request", req, &out); err != nil {
		return out, err
	}
	return out, nil
}

func (c OpsAPIClient) Approve(ctx context.Context, requestID, approver string, timeoutS int) (ActionResponse, error) {
	var out ActionResponse
	body := map[string]any{
		"request_id":      strings.TrimSpace(requestID),
		"approver":        strings.TrimSpace(approver),
		"timeout_seconds": timeoutS,
	}
	if err := c.doJSON(ctx, http.MethodPost, "/actions/approve", body, &out); err != nil {
		return out, err
	}
	return out, nil
}

func (c OpsAPIClient) Reject(ctx context.Context, requestID, approver, reason string) (ActionResponse, error) {
	var out ActionResponse
	body := map[string]any{
		"request_id": strings.TrimSpace(requestID),
		"approver":   strings.TrimSpace(approver),
		"reason":     strings.TrimSpace(reason),
	}
	if err := c.doJSON(ctx, http.MethodPost, "/actions/reject", body, &out); err != nil {
		return out, err
	}
	return out, nil
}

func (c OpsAPIClient) doJSON(ctx context.Context, method, path string, body any, out any) error {
	if c.Client == nil {
		c.Client = &http.Client{Timeout: 20 * time.Second}
	}
	fullURL := strings.TrimRight(c.BaseURL, "/") + path
	var reader io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		reader = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, fullURL, reader)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if strings.TrimSpace(c.Token) != "" {
		req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(c.Token))
	}
	resp, err := c.Client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	if resp.StatusCode >= 300 {
		msg := strings.TrimSpace(string(data))
		if decoded := parseErrorBody(data); decoded != "" {
			msg = decoded
		}
		if msg == "" {
			msg = resp.Status
		}
		return fmt.Errorf("%s %s: %s", method, path, msg)
	}
	if out == nil || len(data) == 0 {
		return nil
	}
	return json.Unmarshal(data, out)
}

func parseErrorBody(data []byte) string {
	var payload map[string]any
	if err := json.Unmarshal(data, &payload); err != nil {
		return ""
	}
	if v, ok := payload["error"].(string); ok {
		return strings.TrimSpace(v)
	}
	return ""
}
