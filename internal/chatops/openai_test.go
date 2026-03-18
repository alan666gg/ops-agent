package chatops

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
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
			if got := body["model"]; got != "gpt-5-mini" {
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
			Model:   "gpt-5-mini",
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

	b, err := os.ReadFile(stateFile)
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.TrimSpace(string(b)); got != "resp_2" {
		t.Fatalf("unexpected persisted response id: %q", got)
	}
}

func TestConversationStateStoreLoadWithEmptyPath(t *testing.T) {
	store := ConversationStateStore{}
	got, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if got != "" {
		t.Fatalf("expected empty state, got %q", got)
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
