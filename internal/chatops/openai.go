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
	"github.com/alan666gg/ops-agent/internal/audit"
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
	Authorizer     Authorizer
	ProjectForEnv  func(string) (string, error)
	State          ConversationStateStore
	Confirmations  ConfirmationStore
	AuditFile      string
	ApproveTimeout int
	MaxToolRounds  int
	ConfirmTTL     time.Duration
	SystemPrompt   string
}

type ConfirmationStore struct {
	Path string
}

type PendingConfirmation struct {
	ToolName  string         `json:"tool_name"`
	Arguments map[string]any `json:"arguments"`
	Summary   string         `json:"summary"`
	CreatedAt time.Time      `json:"created_at"`
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

type toolExecution struct {
	Output      string
	DirectReply string
	Stop        bool
}

func (a Agent) Enabled() bool {
	return strings.TrimSpace(a.OpenAI.APIKey) != ""
}

func (a Agent) Reset() error {
	return a.ResetActor("")
}

func (a Agent) ResetActor(actor string) error {
	if err := a.State.Clear(actor); err != nil {
		return err
	}
	return a.Confirmations.Clear(actor)
}

func (a Agent) Run(ctx context.Context, userInput, actor string) (string, error) {
	if !a.Enabled() {
		return "", fmt.Errorf("llm is not configured")
	}
	previous, _ := a.State.Load(actor)
	text, responseID, err := a.runWithState(ctx, userInput, actor, previous)
	if err != nil && previous != "" && strings.Contains(strings.ToLower(err.Error()), "previous_response_id") {
		_ = a.State.Clear(actor)
		text, responseID, err = a.runWithState(ctx, userInput, actor, "")
	}
	if err != nil {
		return "", err
	}
	if strings.TrimSpace(responseID) != "" {
		_ = a.State.Save(actor, responseID)
	}
	return text, nil
}

func (a Agent) HandleConfirmation(ctx context.Context, userInput, actor string) (string, bool, error) {
	input := strings.TrimSpace(userInput)
	if input == "" {
		return "", false, nil
	}
	if !isConfirmText(input) && !isCancelText(input) {
		return "", false, nil
	}
	pending, ok, err := a.loadPendingConfirmation(actor)
	if err != nil {
		return "", true, err
	}
	if !ok {
		if isConfirmText(input) || isCancelText(input) {
			return "当前没有待确认的高风险操作。", true, nil
		}
		return "", false, nil
	}
	if isCancelText(input) {
		_ = a.Confirmations.Clear(actor)
		a.auditToolEvent(actor, pending.ToolName, pending.Arguments, "cancelled", pending.Summary)
		return "已取消待确认操作：" + pending.Summary, true, nil
	}
	reply, err := a.executeConfirmedTool(ctx, pending, actor)
	if err != nil {
		return "", true, err
	}
	_ = a.Confirmations.Clear(actor)
	_ = a.State.Clear(actor)
	return reply, true, nil
}

func (a Agent) HasPendingConfirmation(actor string) bool {
	_, ok, err := a.loadPendingConfirmation(actor)
	return err == nil && ok
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
			exec := a.executeTool(ctx, call, actor)
			if exec.Stop {
				return exec.DirectReply, lastID, nil
			}
			toolOutputs = append(toolOutputs, toolOutput{
				Type:   "function_call_output",
				CallID: call.CallID,
				Output: exec.Output,
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
					"project": map[string]any{"type": "string", "description": "Optional project scope such as default, payments, or infra."},
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
					"limit":   map[string]any{"type": "integer", "minimum": 1, "maximum": 20},
					"project": map[string]any{"type": "string", "description": "Optional project scope."},
				},
				"required":             []string{"limit"},
				"additionalProperties": false,
			},
		},
		{
			Type:        "function",
			Name:        "list_actions",
			Description: "List recent action requests for one status, such as pending, approved, executed, failed, denied, or expired.",
			Strict:      true,
			Parameters: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"status":  map[string]any{"type": "string"},
					"limit":   map[string]any{"type": "integer", "minimum": 1, "maximum": 20},
					"project": map[string]any{"type": "string", "description": "Optional project scope."},
				},
				"required":             []string{"status", "limit"},
				"additionalProperties": false,
			},
		},
		{
			Type:        "function",
			Name:        "get_action",
			Description: "Get the full detail of one action request by request_id.",
			Strict:      true,
			Parameters: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"request_id": map[string]any{"type": "string"},
				},
				"required":             []string{"request_id"},
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

func (a Agent) executeTool(ctx context.Context, call responseOutputItem, actor string) toolExecution {
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
		return toolExecution{Output: respond(nil, fmt.Errorf("invalid tool arguments: %w", err))}
	}
	if err := a.Authorizer.AuthorizeTool(actor, call.Name, args); err != nil {
		a.auditToolEvent(actor, call.Name, args, "denied", err.Error())
		return toolExecution{Output: respond(nil, err)}
	}
	if a.requiresConfirmation(call.Name, args) {
		pending := PendingConfirmation{
			ToolName:  call.Name,
			Arguments: args,
			Summary:   summarizeToolCall(call.Name, args),
			CreatedAt: time.Now().UTC(),
		}
		if err := a.Confirmations.Save(actor, pending); err != nil {
			return toolExecution{Output: respond(nil, fmt.Errorf("save confirmation: %w", err))}
		}
		a.auditToolEvent(actor, call.Name, args, "confirmation_required", pending.Summary)
		return toolExecution{
			Output: respond(map[string]any{
				"confirmation_required": true,
				"summary":               pending.Summary,
				"instructions":          "ask the user to reply with 确认执行 or 取消",
			}, nil),
			DirectReply: "这个操作属于高风险变更，已进入二次确认。\n待确认内容：" + pending.Summary + "\n\n请回复“确认执行”继续，或回复“取消”放弃。",
			Stop:        true,
		}
	}
	data, _, _, err := a.executeToolCall(ctx, call.Name, args, actor)
	status := "ok"
	if err != nil {
		status = "failed"
	}
	a.auditToolEvent(actor, call.Name, args, status, summarizeToolResult(data, err))
	return toolExecution{Output: respond(data, err)}
}

func (a Agent) executeToolCall(ctx context.Context, name string, args map[string]any, actor string) (any, string, string, error) {
	switch name {
	case "get_health":
		env, _ := args["env"].(string)
		project, err := a.authorizeEnv(actor, env)
		if err != nil {
			return nil, env, "", err
		}
		data, err := a.OpsAPI.Health(ctx, env)
		if data.Project == "" {
			data.Project = project
		}
		return data, env, "", err
	case "get_incident_summary":
		projects, err := a.scopeProjects(actor, stringFromAny(args["project"]))
		if err != nil {
			return nil, "", "", err
		}
		data, err := a.OpsAPI.IncidentSummaryByProject(ctx, intFromAny(args["minutes"], 60), projects)
		return data, "", "", err
	case "list_pending":
		projects, err := a.scopeProjects(actor, stringFromAny(args["project"]))
		if err != nil {
			return nil, "", "", err
		}
		data, err := a.OpsAPI.PendingByProject(ctx, intFromAny(args["limit"], 10), projects)
		return data, "", "", err
	case "list_actions":
		projects, err := a.scopeProjects(actor, stringFromAny(args["project"]))
		if err != nil {
			return nil, "", "", err
		}
		data, err := a.OpsAPI.ListActionsByProject(ctx, stringFromAny(args["status"]), intFromAny(args["limit"], 10), "", projects)
		return data, "", "", err
	case "get_action":
		data, err := a.OpsAPI.GetAction(ctx, stringFromAny(args["request_id"]))
		if err == nil {
			if authErr := a.Authorizer.AuthorizeProject(actor, data.Project); authErr != nil {
				return nil, data.Env, data.TargetHost, authErr
			}
		}
		return data, data.Env, data.TargetHost, err
	case "request_action":
		env := stringFromAny(args["env"])
		targetHost := stringFromAny(args["target_host"])
		if _, err := a.authorizeEnv(actor, env); err != nil {
			return nil, env, targetHost, err
		}
		data, err := a.OpsAPI.RequestAction(ctx, RequestActionRequest{
			Env:        env,
			Action:     stringFromAny(args["action"]),
			TargetHost: targetHost,
			Args:       stringSliceFromAny(args["args"]),
			Actor:      actor,
		})
		return data, env, targetHost, err
	case "approve_action":
		item, err := a.OpsAPI.GetAction(ctx, stringFromAny(args["request_id"]))
		if err != nil {
			return nil, "", "", err
		}
		if err := a.Authorizer.AuthorizeProject(actor, item.Project); err != nil {
			return nil, item.Env, item.TargetHost, err
		}
		timeout := intFromAny(args["timeout_seconds"], a.ApproveTimeout)
		if timeout <= 0 {
			timeout = 30
		}
		data, err := a.OpsAPI.Approve(ctx, item.ID, actor, timeout)
		return data, item.Env, item.TargetHost, err
	case "reject_action":
		item, err := a.OpsAPI.GetAction(ctx, stringFromAny(args["request_id"]))
		if err != nil {
			return nil, "", "", err
		}
		if err := a.Authorizer.AuthorizeProject(actor, item.Project); err != nil {
			return nil, item.Env, item.TargetHost, err
		}
		reason := stringFromAny(args["reason"])
		if strings.TrimSpace(reason) == "" {
			reason = "rejected from llm agent"
		}
		data, err := a.OpsAPI.Reject(ctx, item.ID, actor, reason)
		return data, item.Env, item.TargetHost, err
	default:
		return nil, "", "", fmt.Errorf("unsupported tool %q", name)
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
	b.WriteString("Respect project isolation. If a project is ambiguous, ask one short follow-up question instead of guessing.\n")
	b.WriteString("Before approving or rejecting an ambiguous request, prefer listing or fetching request details first.\n")
	b.WriteString("Only approve_action or reject_action when the user explicitly asks to approve or reject.\n")
	b.WriteString("When the user asks to run an operation, prefer request_action so policy and approval stay enforced.\n")
	b.WriteString("If a tool result says confirmation_required, do not call more tools. Ask the user to reply exactly with 确认执行 or 取消.\n")
	b.WriteString("If required information is missing, ask one concise follow-up question.\n")
	b.WriteString("Keep answers concise and operationally clear.\n")
	b.WriteString("Available actions: ")
	b.WriteString(strings.Join(actions.Names(), ", "))
	return b.String()
}

func (a Agent) authorizeEnv(actor, env string) (string, error) {
	project, err := a.projectForEnv(env)
	if err != nil {
		return "", err
	}
	if err := a.Authorizer.AuthorizeProject(actor, project); err != nil {
		return "", err
	}
	return project, nil
}

func (a Agent) projectForEnv(env string) (string, error) {
	env = strings.TrimSpace(env)
	if env == "" {
		return "default", nil
	}
	if a.ProjectForEnv == nil {
		return "default", nil
	}
	project, err := a.ProjectForEnv(env)
	if err != nil {
		return "", err
	}
	project = strings.TrimSpace(project)
	if project == "" {
		project = "default"
	}
	return project, nil
}

func (a Agent) scopeProjects(actor, requested string) ([]string, error) {
	if strings.TrimSpace(requested) != "" {
		if err := a.Authorizer.AuthorizeProject(actor, requested); err != nil {
			return nil, err
		}
		return []string{strings.TrimSpace(requested)}, nil
	}
	return a.Authorizer.AllowedProjects(actor)
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

func (s ConversationStateStore) Load(actor string) (string, error) {
	path := s.pathFor(actor)
	if strings.TrimSpace(path) == "" {
		return "", nil
	}
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return "", nil
		}
		return "", err
	}
	return strings.TrimSpace(string(b)), nil
}

func (s ConversationStateStore) Save(actor, id string) error {
	path := s.pathFor(actor)
	if strings.TrimSpace(path) == "" {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return os.WriteFile(path, []byte(strings.TrimSpace(id)), 0o644)
}

func (s ConversationStateStore) Clear(actor string) error {
	path := s.pathFor(actor)
	if strings.TrimSpace(path) == "" {
		return nil
	}
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

func (s ConversationStateStore) pathFor(actor string) string {
	if strings.TrimSpace(s.Path) == "" {
		return ""
	}
	if strings.TrimSpace(actor) == "" {
		return s.Path
	}
	dir := filepath.Dir(s.Path)
	base := filepath.Base(s.Path)
	ext := filepath.Ext(base)
	name := strings.TrimSuffix(base, ext)
	if name == "" {
		name = "state"
	}
	return filepath.Join(dir, name+"__"+safeFileKey(actor)+ext)
}

func (s ConfirmationStore) Load(actor string) (PendingConfirmation, bool, error) {
	path := s.pathFor(actor)
	if strings.TrimSpace(path) == "" {
		return PendingConfirmation{}, false, nil
	}
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return PendingConfirmation{}, false, nil
		}
		return PendingConfirmation{}, false, err
	}
	var pending PendingConfirmation
	if err := json.Unmarshal(b, &pending); err != nil {
		return PendingConfirmation{}, false, err
	}
	return pending, true, nil
}

func (s ConfirmationStore) Save(actor string, pending PendingConfirmation) error {
	path := s.pathFor(actor)
	if strings.TrimSpace(path) == "" {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	b, err := json.MarshalIndent(pending, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0o644)
}

func (s ConfirmationStore) Clear(actor string) error {
	path := s.pathFor(actor)
	if strings.TrimSpace(path) == "" {
		return nil
	}
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

func (s ConfirmationStore) pathFor(actor string) string {
	if strings.TrimSpace(s.Path) == "" {
		return ""
	}
	if strings.TrimSpace(actor) == "" {
		return s.Path
	}
	dir := filepath.Dir(s.Path)
	base := filepath.Base(s.Path)
	ext := filepath.Ext(base)
	name := strings.TrimSuffix(base, ext)
	if name == "" {
		name = "confirmation"
	}
	return filepath.Join(dir, name+"__"+safeFileKey(actor)+ext)
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

func (a Agent) requiresConfirmation(toolName string, args map[string]any) bool {
	switch toolName {
	case "approve_action", "reject_action":
		return true
	case "request_action":
		action := stringFromAny(args["action"])
		return !strings.HasPrefix(action, "check_")
	default:
		return false
	}
}

func (a Agent) loadPendingConfirmation(actor string) (PendingConfirmation, bool, error) {
	pending, ok, err := a.Confirmations.Load(actor)
	if err != nil || !ok {
		return pending, ok, err
	}
	ttl := a.ConfirmTTL
	if ttl <= 0 {
		ttl = 10 * time.Minute
	}
	if pending.CreatedAt.IsZero() || time.Since(pending.CreatedAt) <= ttl {
		return pending, true, nil
	}
	_ = a.Confirmations.Clear(actor)
	return PendingConfirmation{}, false, nil
}

func (a Agent) executeConfirmedTool(ctx context.Context, pending PendingConfirmation, actor string) (string, error) {
	if err := a.Authorizer.AuthorizeTool(actor, pending.ToolName, pending.Arguments); err != nil {
		a.auditToolEvent(actor, pending.ToolName, pending.Arguments, "denied", err.Error())
		return "", err
	}
	data, _, _, err := a.executeToolCall(ctx, pending.ToolName, pending.Arguments, actor)
	status := "ok"
	if err != nil {
		status = "failed"
	}
	a.auditToolEvent(actor, pending.ToolName, pending.Arguments, "confirmation_executed", pending.Summary)
	a.auditToolEvent(actor, pending.ToolName, pending.Arguments, status, summarizeToolResult(data, err))
	if err != nil {
		return "", err
	}
	switch pending.ToolName {
	case "request_action":
		resp, _ := data.(RequestActionResponse)
		return fmt.Sprintf("已确认并提交操作。\nstatus=%s\nrequest_id=%s\nmessage=%s", resp.Status, defaultString(resp.RequestID, "(none)"), strings.TrimSpace(resp.Message)), nil
	case "approve_action":
		resp, _ := data.(ActionResponse)
		return fmt.Sprintf("已确认并批准请求。\nstatus=%s\nmessage=%s", resp.Status, strings.TrimSpace(resp.Message)), nil
	case "reject_action":
		resp, _ := data.(ActionResponse)
		return fmt.Sprintf("已确认并拒绝请求。\nstatus=%s\nmessage=%s", resp.Status, strings.TrimSpace(resp.Message)), nil
	default:
		return "已确认执行。", nil
	}
}

func (a Agent) auditToolEvent(actor, toolName string, args map[string]any, status, message string) {
	if strings.TrimSpace(a.AuditFile) == "" {
		return
	}
	env := stringFromAny(args["env"])
	targetHost := stringFromAny(args["target_host"])
	target := toolName
	if reqID := stringFromAny(args["request_id"]); reqID != "" {
		target = reqID
	}
	_ = os.MkdirAll(filepath.Dir(a.AuditFile), 0o755)
	_ = audit.AppendJSONL(a.AuditFile, audit.Event{
		Time:       time.Now().UTC(),
		Actor:      actor,
		Action:     "llm_" + toolName,
		Env:        env,
		TargetHost: targetHost,
		Target:     target,
		Status:     status,
		Message:    trimForAudit(message),
	})
}

func summarizeToolCall(toolName string, args map[string]any) string {
	switch toolName {
	case "request_action":
		parts := []string{"request_action"}
		if env := stringFromAny(args["env"]); env != "" {
			parts = append(parts, "env="+env)
		}
		if action := stringFromAny(args["action"]); action != "" {
			parts = append(parts, "action="+action)
		}
		if host := stringFromAny(args["target_host"]); host != "" {
			parts = append(parts, "target_host="+host)
		}
		if items := stringSliceFromAny(args["args"]); len(items) > 0 {
			parts = append(parts, "args="+strings.Join(items, ","))
		}
		return strings.Join(parts, " ")
	case "approve_action":
		return "approve_action request_id=" + stringFromAny(args["request_id"])
	case "reject_action":
		summary := "reject_action request_id=" + stringFromAny(args["request_id"])
		if reason := stringFromAny(args["reason"]); reason != "" {
			summary += " reason=" + reason
		}
		return summary
	default:
		b, _ := json.Marshal(args)
		return toolName + " " + trimForAudit(string(b))
	}
}

func summarizeToolResult(data any, err error) string {
	if err != nil {
		return err.Error()
	}
	b, marshalErr := json.Marshal(data)
	if marshalErr != nil {
		return "ok"
	}
	return string(b)
}

func isConfirmText(v string) bool {
	v = strings.ToLower(strings.TrimSpace(v))
	switch v {
	case "确认", "确认执行", "确认一下", "yes", "yes confirm", "confirm":
		return true
	default:
		return false
	}
}

func isCancelText(v string) bool {
	v = strings.ToLower(strings.TrimSpace(v))
	switch v {
	case "取消", "取消执行", "算了", "cancel", "abort", "no":
		return true
	default:
		return false
	}
}

func safeFileKey(v string) string {
	v = strings.TrimSpace(v)
	if v == "" {
		return "default"
	}
	var b strings.Builder
	for _, r := range v {
		switch {
		case r >= 'a' && r <= 'z':
			b.WriteRune(r)
		case r >= 'A' && r <= 'Z':
			b.WriteRune(r + ('a' - 'A'))
		case r >= '0' && r <= '9':
			b.WriteRune(r)
		default:
			b.WriteByte('_')
		}
	}
	out := strings.Trim(b.String(), "_")
	if out == "" {
		return "default"
	}
	return out
}

func trimForAudit(v string) string {
	v = strings.TrimSpace(v)
	if len(v) <= 500 {
		return v
	}
	return v[:497] + "..."
}
