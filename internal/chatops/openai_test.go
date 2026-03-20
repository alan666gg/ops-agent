package chatops

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestAgentRunExecutesToolCallAndPersistsResponseID(t *testing.T) {
	var openAIRequests []map[string]any
	openAIClient := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if got := r.Header.Get("Authorization"); got != "Bearer test-key" {
			t.Fatalf("unexpected auth header: %q", got)
		}
		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		openAIRequests = append(openAIRequests, body)
		var payload any
		switch len(openAIRequests) {
		case 1:
			if got := body["model"]; got != "gpt-5.4" {
				t.Fatalf("unexpected model: %#v", got)
			}
			if _, ok := body["tools"].([]any); !ok {
				t.Fatalf("expected tools in first request: %#v", body["tools"])
			}
			payload = map[string]any{
				"id": "resp_1",
				"output": []map[string]any{
					{
						"type":      "function_call",
						"name":      "get_health",
						"call_id":   "call_1",
						"arguments": `{"env":"prod"}`,
					},
				},
			}
		case 2:
			if got := body["previous_response_id"]; got != "resp_1" {
				t.Fatalf("unexpected previous_response_id: %#v", got)
			}
			input, ok := body["input"].([]any)
			if !ok || len(input) != 1 {
				t.Fatalf("unexpected tool output input: %#v", body["input"])
			}
			toolOutput, ok := input[0].(map[string]any)
			if !ok || toolOutput["call_id"] != "call_1" {
				t.Fatalf("unexpected tool output payload: %#v", input[0])
			}
			payload = map[string]any{
				"id":          "resp_2",
				"output_text": "prod 当前不健康，建议先看 host 与 service 健康状态。",
			}
		default:
			t.Fatalf("unexpected extra OpenAI request %d", len(openAIRequests))
		}
		return jsonHTTPResponse(http.StatusOK, payload), nil
	})}

	opsAPIClient := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if r.URL.Path != "/health/run" {
			t.Fatalf("unexpected ops-api path: %s", r.URL.Path)
		}
		if got := r.URL.Query().Get("env"); got != "prod" {
			t.Fatalf("unexpected env query: %q", got)
		}
		return jsonHTTPResponse(http.StatusOK, HealthResponse{
			Env:     "prod",
			Status:  "fail",
			Summary: "prod has 1 failed check",
		}), nil
	})}

	stateFile := filepath.Join(t.TempDir(), "telegram-response-id.txt")
	agent := Agent{
		OpenAI: OpenAIClient{
			APIKey:  "test-key",
			BaseURL: "http://openai.test",
			Model:   "gpt-5.4",
			Client:  openAIClient,
		},
		OpsAPI: OpsAPIClient{
			BaseURL: "http://ops-api.test",
			Client:  opsAPIClient,
		},
		State:          ConversationStateStore{Path: stateFile},
		ApproveTimeout: 30,
		MaxToolRounds:  3,
	}

	reply, err := agent.Run(context.Background(), "prod 现在怎么样", "tg:@ops")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(reply, "prod 当前不健康") {
		t.Fatalf("unexpected reply: %q", reply)
	}
	if len(openAIRequests) != 2 {
		t.Fatalf("expected 2 OpenAI requests, got %d", len(openAIRequests))
	}

	b, err := os.ReadFile(agent.State.pathFor("tg:@ops"))
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.TrimSpace(string(b)); got != "resp_2" {
		t.Fatalf("unexpected persisted response id: %q", got)
	}
}

func TestConversationStateStoreLoadWithEmptyPath(t *testing.T) {
	store := ConversationStateStore{}
	got, err := store.Load("tg:@ops")
	if err != nil {
		t.Fatal(err)
	}
	if got != "" {
		t.Fatalf("expected empty state, got %q", got)
	}
}

func TestConversationStateStoreSeparatesActors(t *testing.T) {
	store := ConversationStateStore{Path: filepath.Join(t.TempDir(), "state.txt")}
	if err := store.Save("tg:@alice", "resp_a"); err != nil {
		t.Fatal(err)
	}
	if err := store.Save("tg:@bob", "resp_b"); err != nil {
		t.Fatal(err)
	}
	gotA, err := store.Load("tg:@alice")
	if err != nil {
		t.Fatal(err)
	}
	gotB, err := store.Load("tg:@bob")
	if err != nil {
		t.Fatal(err)
	}
	if gotA != "resp_a" || gotB != "resp_b" {
		t.Fatalf("unexpected actor states: %q %q", gotA, gotB)
	}
}

func TestAgentRequiresConfirmationForMutatingTool(t *testing.T) {
	openAIClient := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		return jsonHTTPResponse(http.StatusOK, map[string]any{
			"id": "resp_1",
			"output": []map[string]any{
				{
					"type":      "function_call",
					"name":      "request_action",
					"call_id":   "call_1",
					"arguments": `{"env":"prod","action":"restart_container","target_host":"app-1","args":["cicdtest-app"]}`,
				},
			},
		}), nil
	})}

	opsAPIClient := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		return nil, errors.New("ops-api should not be called before confirmation")
	})}

	tempDir := t.TempDir()
	agent := Agent{
		OpenAI: OpenAIClient{
			APIKey:  "test-key",
			BaseURL: "http://openai.test",
			Model:   "gpt-5.4",
			Client:  openAIClient,
		},
		OpsAPI:        OpsAPIClient{BaseURL: "http://ops-api.test", Client: opsAPIClient},
		State:         ConversationStateStore{Path: filepath.Join(tempDir, "state.txt")},
		Confirmations: ConfirmationStore{Path: filepath.Join(tempDir, "confirm.json")},
		AuditFile:     filepath.Join(tempDir, "audit.jsonl"),
		MaxToolRounds: 3,
		ConfirmTTL:    10 * time.Minute,
	}

	reply, err := agent.Run(context.Background(), "重启 prod 上 app-1 的 cicdtest-app", "tg:@ops")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(reply, "二次确认") {
		t.Fatalf("unexpected confirmation reply: %q", reply)
	}

	pending, ok, err := agent.Confirmations.Load("tg:@ops")
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("expected pending confirmation")
	}
	if pending.ToolName != "request_action" || pending.Summary == "" {
		t.Fatalf("unexpected pending confirmation: %+v", pending)
	}
}

func TestAgentHandleConfirmationExecutesPendingTool(t *testing.T) {
	var called bool
	opsAPIClient := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		called = true
		if r.URL.Path != "/actions/request" {
			t.Fatalf("unexpected ops-api path: %s", r.URL.Path)
		}
		var body RequestActionRequest
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		if body.Action != "restart_container" || body.Env != "prod" || body.TargetHost != "app-1" {
			t.Fatalf("unexpected request body: %+v", body)
		}
		return jsonHTTPResponse(http.StatusOK, RequestActionResponse{
			Status:    "pending",
			Message:   "approval required",
			RequestID: "req_123",
		}), nil
	})}

	tempDir := t.TempDir()
	agent := Agent{
		OpsAPI: OpsAPIClient{
			BaseURL: "http://ops-api.test",
			Client:  opsAPIClient,
		},
		State:          ConversationStateStore{Path: filepath.Join(tempDir, "state.txt")},
		Confirmations:  ConfirmationStore{Path: filepath.Join(tempDir, "confirm.json")},
		AuditFile:      filepath.Join(tempDir, "audit.jsonl"),
		ApproveTimeout: 30,
		ConfirmTTL:     10 * time.Minute,
	}
	err := agent.Confirmations.Save("tg:@ops", PendingConfirmation{
		ToolName: "request_action",
		Arguments: map[string]any{
			"env":         "prod",
			"action":      "restart_container",
			"target_host": "app-1",
			"args":        []string{"cicdtest-app"},
		},
		Summary:   "request_action env=prod action=restart_container target_host=app-1 args=cicdtest-app",
		CreatedAt: time.Now().UTC(),
	})
	if err != nil {
		t.Fatal(err)
	}

	reply, handled, err := agent.HandleConfirmation(context.Background(), "确认执行", "tg:@ops")
	if err != nil {
		t.Fatal(err)
	}
	if !handled {
		t.Fatal("expected confirmation to be handled")
	}
	if !called {
		t.Fatal("expected pending tool to execute")
	}
	if !strings.Contains(reply, "已确认并提交操作") || !strings.Contains(reply, "req_123") {
		t.Fatalf("unexpected confirmation reply: %q", reply)
	}
	if _, ok, err := agent.Confirmations.Load("tg:@ops"); err != nil || ok {
		t.Fatalf("expected confirmation to be cleared, ok=%t err=%v", ok, err)
	}
}

func jsonHTTPResponse(status int, payload any) *http.Response {
	b, _ := json.Marshal(payload)
	return &http.Response{
		StatusCode: status,
		Header:     make(http.Header),
		Body:       io.NopCloser(bytes.NewReader(b)),
	}
}
