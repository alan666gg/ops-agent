package chatops

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/alan666gg/ops-agent/internal/actions"
)

type OpenAIClient struct {
	APIKey  string
	BaseURL string
	Model   string
	Client  *http.Client
}

type ConversationStateStore struct {
	Path string
}

type Agent struct {
	OpenAI         OpenAIClient
	OpsAPI         OpsAPIClient
	State          ConversationStateStore
	ApproveTimeout int
	MaxToolRounds  int
	SystemPrompt   string
}

type responseRequest struct {
	Model              string         `json:"model"`
	Instructions       string         `json:"instructions,omitempty"`
	Input              any            `json:"input"`
	Tools              []responseTool `json:"tools,omitempty"`
	ToolChoice         string         `json:"tool_choice,omitempty"`
	ParallelToolCalls  bool           `json:"parallel_tool_calls,omitempty"`
	PreviousResponseID string         `json:"previous_response_id,omitempty"`
	MaxOutputTokens    int            `json:"max_output_tokens,omitempty"`
}

type responseTool struct {
	Type        string         `json:"type"`
	Name        string         `json:"name"`
	Description string         `json:"description,omitempty"`
	Parameters  map[string]any `json:"parameters,omitempty"`
	Strict      bool           `json:"strict,omitempty"`
}

type responseAPIResponse struct {
	ID         string               `json:"id"`
	OutputText string               `json:"output_text,omitempty"`
	Output     []responseOutputItem `json:"output"`
	Error      *responseError       `json:"error,omitempty"`
}

type responseOutputItem struct {
	Type      string                  `json:"type"`
	Name      string                  `json:"name,omitempty"`
	CallID    string                  `json:"call_id,omitempty"`
	Arguments string                  `json:"arguments,omitempty"`
	Content   []responseMessageOutput `json:"content,omitempty"`
}

type responseMessageOutput struct {
	Type string `json:"type"`
	Text string `json:"text,omitempty"`
}

type responseError struct {
	Message string `json:"message"`
}

type toolOutput struct {
	Type   string `json:"type"`
	CallID string `json:"call_id"`
	Output string `json:"output"`
}

func (a Agent) Enabled() bool {
	return strings.TrimSpace(a.OpenAI.APIKey) != ""
}

func (a Agent) Reset() error {
	return a.State.Clear()
}

func (a Agent) Run(ctx context.Context, userInput, actor string) (string, error) {
	if !a.Enabled() {
		return "", fmt.Errorf("llm is not configured")
	}
	previous, _ := a.State.Load()
	text, responseID, err := a.runWithState(ctx, userInput, actor, previous)
	if err != nil && previous != "" && strings.Contains(strings.ToLower(err.Error()), "previous_response_id") {
		_ = a.State.Clear()
		text, responseID, err = a.runWithState(ctx, userInput, actor, "")
	}
	if err != nil {
		return "", err
	}
	if strings.TrimSpace(responseID) != "" {
		_ = a.State.Save(responseID)
	}
	return text, nil
}

func (a Agent) runWithState(ctx context.Context, userInput, actor, previous string) (string, string, error) {
	maxRounds := a.MaxToolRounds
	if maxRounds <= 0 {
		maxRounds = 6
	}
	tools := a.toolSchemas()
	req := responseRequest{
		Model:              a.modelOrDefault(),
		Instructions:       a.prompt(),
		Input:              userInput,
		Tools:              tools,
		ToolChoice:         "auto",
		ParallelToolCalls:  false,
		PreviousResponseID: strings.TrimSpace(previous),
		MaxOutputTokens:    1200,
	}
	resp, err := a.OpenAI.Create(ctx, req)
	if err != nil {
		return "", "", err
	}
	lastID := resp.ID
	for round := 0; round < maxRounds; round++ {
		calls := functionCalls(resp)
		if len(calls) == 0 {
			text := extractOutputText(resp)
			if strings.TrimSpace(text) == "" {
				text = "我处理完了，但当前没有可展示的文本结果。可以试试 /health prod 或再具体描述一下。"
			}
			return text, lastID, nil
		}
		toolOutputs := make([]toolOutput, 0, len(calls))
		for _, call := range calls {
			output := a.executeTool(ctx, call, actor)
			toolOutputs = append(toolOutputs, toolOutput{
				Type:   "function_call_output",
				CallID: call.CallID,
				Output: output,
			})
		}
		resp, err = a.OpenAI.Create(ctx, responseRequest{
			Model:              a.modelOrDefault(),
			Instructions:       a.prompt(),
			Input:              toolOutputs,
			Tools:              tools,
			ToolChoice:         "auto",
			ParallelToolCalls:  false,
			PreviousResponseID: resp.ID,
			MaxOutputTokens:    1200,
		})
		if err != nil {
			return "", lastID, err
		}
		lastID = resp.ID
	}
	return "", lastID, fmt.Errorf("tool loop exceeded %d rounds", maxRounds)
}

func (a Agent) toolSchemas() []responseTool {
	actionNames := actions.Names()
	return []responseTool{
		{
			Type:        "function",
			Name:        "get_health",
			Description: "Get current health, synthetic SLO checks, suppressed checks, and suggestions for one environment.",
			Strict:      true,
			Parameters: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"env": map[string]any{"type": "string", "description": "Environment name such as test, prod, or production."},
				},
				"required":             []string{"env"},
				"additionalProperties": false,
			},
		},
		{
			Type:        "function",
			Name:        "get_incident_summary",
			Description: "Get incident summary counts for a recent time window in minutes.",
			Strict:      true,
			Parameters: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"minutes": map[string]any{"type": "integer", "minimum": 1, "maximum": 1440},
				},
				"required":             []string{"minutes"},
				"additionalProperties": false,
			},
		},
		{
			Type:        "function",
			Name:        "list_pending",
			Description: "List pending approval requests.",
			Strict:      true,
			Parameters: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"limit": map[string]any{"type": "integer", "minimum": 1, "maximum": 20},
				},
				"required":             []string{"limit"},
				"additionalProperties": false,
			},
		},
		{
			Type:        "function",
			Name:        "request_action",
			Description: "Create an action request. The request may auto-execute low-risk actions or stay pending for approval.",
			Strict:      true,
			Parameters: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"env":         map[string]any{"type": "string"},
					"action":      map[string]any{"type": "string", "enum": actionNames},
					"target_host": map[string]any{"type": "string"},
					"args":        map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
				},
				"required":             []string{"env", "action"},
				"additionalProperties": false,
			},
		},
		{
			Type:        "function",
			Name:        "approve_action",
			Description: "Approve one pending request by request_id. Only use this when the user explicitly asks to approve.",
			Strict:      true,
			Parameters: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"request_id":      map[string]any{"type": "string"},
					"timeout_seconds": map[string]any{"type": "integer", "minimum": 1, "maximum": 120},
				},
				"required":             []string{"request_id"},
				"additionalProperties": false,
			},
		},
		{
			Type:        "function",
			Name:        "reject_action",
			Description: "Reject one pending request by request_id. Only use this when the user explicitly asks to reject.",
			Strict:      true,
			Parameters: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"request_id": map[string]any{"type": "string"},
					"reason":     map[string]any{"type": "string"},
				},
				"required":             []string{"request_id"},
				"additionalProperties": false,
			},
		},
	}
}

func (a Agent) executeTool(ctx context.Context, call responseOutputItem, actor string) string {
	respond := func(data any, err error) string {
		payload := map[string]any{"ok": err == nil}
		if err != nil {
			payload["error"] = err.Error()
		} else {
			payload["data"] = data
		}
		b, _ := json.Marshal(payload)
		return string(b)
	}

	var args map[string]any
	if err := json.Unmarshal([]byte(call.Arguments), &args); err != nil {
		return respond(nil, fmt.Errorf("invalid tool arguments: %w", err))
	}
	switch call.Name {
	case "get_health":
		env, _ := args["env"].(string)
		data, err := a.OpsAPI.Health(ctx, env)
		return respond(data, err)
	case "get_incident_summary":
		data, err := a.OpsAPI.IncidentSummary(ctx, intFromAny(args["minutes"], 60))
		return respond(data, err)
	case "list_pending":
		data, err := a.OpsAPI.Pending(ctx, intFromAny(args["limit"], 10))
		return respond(data, err)
	case "request_action":
		data, err := a.OpsAPI.RequestAction(ctx, RequestActionRequest{
			Env:        stringFromAny(args["env"]),
			Action:     stringFromAny(args["action"]),
			TargetHost: stringFromAny(args["target_host"]),
			Args:       stringSliceFromAny(args["args"]),
			Actor:      actor,
		})
		return respond(data, err)
	case "approve_action":
		timeout := intFromAny(args["timeout_seconds"], a.ApproveTimeout)
		if timeout <= 0 {
			timeout = 30
		}
		data, err := a.OpsAPI.Approve(ctx, stringFromAny(args["request_id"]), actor, timeout)
		return respond(data, err)
	case "reject_action":
		reason := stringFromAny(args["reason"])
		if strings.TrimSpace(reason) == "" {
			reason = "rejected from llm agent"
		}
		data, err := a.OpsAPI.Reject(ctx, stringFromAny(args["request_id"]), actor, reason)
		return respond(data, err)
	default:
		return respond(nil, fmt.Errorf("unsupported tool %q", call.Name))
	}
}

func (a Agent) prompt() string {
	if strings.TrimSpace(a.SystemPrompt) != "" {
		return a.SystemPrompt
	}
	var b strings.Builder
	b.WriteString("You are the Telegram operations assistant for ops-agent.\n")
	b.WriteString("Respond in the user's language, defaulting to Chinese.\n")
	b.WriteString("Use tools whenever the user asks about health, incidents, pending approvals, or actions.\n")
	b.WriteString("Never invent request IDs, environments, host names, or action names.\n")
	b.WriteString("Only approve_action or reject_action when the user explicitly asks to approve or reject.\n")
	b.WriteString("When the user asks to run an operation, prefer request_action so policy and approval stay enforced.\n")
	b.WriteString("If required information is missing, ask one concise follow-up question.\n")
	b.WriteString("Keep answers concise and operationally clear.\n")
	b.WriteString("Available actions: ")
	b.WriteString(strings.Join(actions.Names(), ", "))
	return b.String()
}

func (a Agent) modelOrDefault() string {
	if strings.TrimSpace(a.OpenAI.Model) != "" {
		return strings.TrimSpace(a.OpenAI.Model)
	}
	return "gpt-5-mini"
}

func (c OpenAIClient) Create(ctx context.Context, req responseRequest) (responseAPIResponse, error) {
	var out responseAPIResponse
	if strings.TrimSpace(c.APIKey) == "" {
		return out, fmt.Errorf("openai api key is empty")
	}
	if strings.TrimSpace(req.Model) == "" {
		req.Model = "gpt-5-mini"
	}
	if c.Client == nil {
		c.Client = &http.Client{Timeout: 40 * time.Second}
	}
	base := strings.TrimSpace(c.BaseURL)
	if base == "" {
		base = "https://api.openai.com/v1"
	}
	b, err := json.Marshal(req)
	if err != nil {
		return out, err
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(base, "/")+"/responses", bytes.NewReader(b))
	if err != nil {
		return out, err
	}
	httpReq.Header.Set("Authorization", "Bearer "+strings.TrimSpace(c.APIKey))
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Accept", "application/json")

	resp, err := c.Client.Do(httpReq)
	if err != nil {
		return out, err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return out, err
	}
	if err := json.Unmarshal(data, &out); err != nil {
		return out, err
	}
	if resp.StatusCode >= 300 {
		msg := strings.TrimSpace(string(data))
		if out.Error != nil && strings.TrimSpace(out.Error.Message) != "" {
			msg = out.Error.Message
		}
		return responseAPIResponse{}, fmt.Errorf("openai responses api: %s", msg)
	}
	return out, nil
}

func (s ConversationStateStore) Load() (string, error) {
	if strings.TrimSpace(s.Path) == "" {
		return "", nil
	}
	b, err := os.ReadFile(s.Path)
	if err != nil {
		if os.IsNotExist(err) {
			return "", nil
		}
		return "", err
	}
	return strings.TrimSpace(string(b)), nil
}

func (s ConversationStateStore) Save(id string) error {
	if strings.TrimSpace(s.Path) == "" {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(s.Path), 0o755); err != nil {
		return err
	}
	return os.WriteFile(s.Path, []byte(strings.TrimSpace(id)), 0o644)
}

func (s ConversationStateStore) Clear() error {
	if strings.TrimSpace(s.Path) == "" {
		return nil
	}
	if err := os.Remove(s.Path); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

func functionCalls(resp responseAPIResponse) []responseOutputItem {
	var out []responseOutputItem
	for _, item := range resp.Output {
		if item.Type == "function_call" {
			out = append(out, item)
		}
	}
	return out
}

func extractOutputText(resp responseAPIResponse) string {
	if strings.TrimSpace(resp.OutputText) != "" {
		return strings.TrimSpace(resp.OutputText)
	}
	var parts []string
	for _, item := range resp.Output {
		if item.Type != "message" {
			continue
		}
		for _, content := range item.Content {
			if (content.Type == "output_text" || content.Type == "text") && strings.TrimSpace(content.Text) != "" {
				parts = append(parts, strings.TrimSpace(content.Text))
			}
		}
	}
	return strings.Join(parts, "\n")
}

func intFromAny(v any, fallback int) int {
	switch x := v.(type) {
	case float64:
		return int(x)
	case int:
		return x
	case json.Number:
		n, err := x.Int64()
		if err == nil {
			return int(n)
		}
	case string:
		n, err := strconv.Atoi(strings.TrimSpace(x))
		if err == nil {
			return n
		}
	}
	return fallback
}

func stringFromAny(v any) string {
	if s, ok := v.(string); ok {
		return strings.TrimSpace(s)
	}
	return ""
}

func stringSliceFromAny(v any) []string {
	raw, ok := v.([]any)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(raw))
	for _, item := range raw {
		if s, ok := item.(string); ok && strings.TrimSpace(s) != "" {
			out = append(out, strings.TrimSpace(s))
		}
	}
	return out
}
