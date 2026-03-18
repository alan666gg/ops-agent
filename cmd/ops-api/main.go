package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/alan666gg/ops-agent/internal/actions"
	"github.com/alan666gg/ops-agent/internal/approval"
	"github.com/alan666gg/ops-agent/internal/audit"
	"github.com/alan666gg/ops-agent/internal/checks"
	"github.com/alan666gg/ops-agent/internal/config"
	rbexec "github.com/alan666gg/ops-agent/internal/exec"
	"github.com/alan666gg/ops-agent/internal/incident"
	"github.com/alan666gg/ops-agent/internal/notify"
	"github.com/alan666gg/ops-agent/internal/policy"
)

type approvalBackend interface {
	Create(r approval.Request) error
	Update(id string, update func(*approval.Request) error) (approval.Request, error)
	ListPending(limit int) ([]approval.Request, error)
	ListByStatus(status string, limit int) ([]approval.Request, error)
	ExpirePendingOlderThan(ttl time.Duration) (int64, error)
}

type server struct {
	envFile       string
	policyFile    string
	auditFile     string
	token         string
	approvalStore approvalBackend
	metrics       *apiMetrics
	limiter       *rateLimiter
	notifier      notify.Notifier
	notifyMin     string
	mu            sync.Mutex
}

type apiMetrics struct {
	mu               sync.Mutex
	requestsTotal    map[string]int64
	errorsTotal      map[string]int64
	durationMsTotal  map[string]float64
	actionsTotal     map[string]int64
	actionsFailTotal map[string]int64
}

type statusWriter struct {
	http.ResponseWriter
	status int
}

func (w *statusWriter) WriteHeader(code int) {
	w.status = code
	w.ResponseWriter.WriteHeader(code)
}

type rateLimiter struct {
	mu       sync.Mutex
	window   time.Duration
	max      int
	requests map[string][]time.Time
}

func newRateLimiter(window time.Duration, max int) *rateLimiter {
	if window <= 0 {
		window = 1 * time.Minute
	}
	if max <= 0 {
		max = 120
	}
	return &rateLimiter{window: window, max: max, requests: map[string][]time.Time{}}
}

func (l *rateLimiter) allow(key string) bool {
	now := time.Now()
	cutoff := now.Add(-l.window)
	l.mu.Lock()
	defer l.mu.Unlock()
	arr := l.requests[key]
	k := 0
	for _, t := range arr {
		if t.After(cutoff) {
			arr[k] = t
			k++
		}
	}
	arr = arr[:k]
	if len(arr) >= l.max {
		l.requests[key] = arr
		return false
	}
	arr = append(arr, now)
	l.requests[key] = arr
	return true
}

type actionRequest struct {
	Action     string   `json:"action"`
	Env        string   `json:"env,omitempty"`
	TargetHost string   `json:"target_host,omitempty"`
	Args       []string `json:"args"`
	Approved   bool     `json:"approved"`
	Actor      string   `json:"actor"`
	TimeoutS   int      `json:"timeout_seconds"`
}

type requestActionResponse struct {
	Status    string `json:"status"`
	Message   string `json:"message"`
	RequestID string `json:"request_id,omitempty"`
}

type approveRequest struct {
	RequestID string `json:"request_id"`
	Approver  string `json:"approver"`
	TimeoutS  int    `json:"timeout_seconds"`
}

type rejectRequest struct {
	RequestID string `json:"request_id"`
	Approver  string `json:"approver"`
	Reason    string `json:"reason"`
}

type actionResponse struct {
	Status   string `json:"status"`
	Message  string `json:"message"`
	ExitCode int    `json:"exit_code,omitempty"`
	Output   string `json:"output,omitempty"`
}

type incidentSummary struct {
	WindowMinutes int            `json:"window_minutes"`
	Total         int            `json:"total_events"`
	ByStatus      map[string]int `json:"by_status"`
	TopTargets    []string       `json:"top_targets"`
}

func main() {
	addr := flag.String("addr", ":8090", "http listen addr")
	envFile := flag.String("env-file", "configs/environments.yaml", "path to environments yaml")
	policyFile := flag.String("policy", "configs/policies.yaml", "path to policy yaml")
	auditFile := flag.String("audit", "audit/api.jsonl", "audit output jsonl")
	pendingFile := flag.String("pending-file", "audit/pending-actions.db", "pending approval requests store path")
	pendingDriver := flag.String("pending-driver", "sqlite", "pending store driver: sqlite|json")
	pendingTTL := flag.Duration("pending-ttl", 24*time.Hour, "expire pending requests older than this duration (0 to disable)")
	rateLimitWindow := flag.Duration("rate-limit-window", time.Minute, "rate limit window")
	rateLimitMax := flag.Int("rate-limit-max", 120, "max requests per client per window")
	notifyWebhook := flag.String("notify-webhook", "", "generic webhook URL for health incident notifications")
	slackWebhook := flag.String("notify-slack-webhook", "", "Slack incoming webhook URL for health incident notifications")
	telegramBotToken := flag.String("notify-telegram-bot-token", "", "Telegram bot token for health incident notifications")
	telegramChatID := flag.String("notify-telegram-chat-id", "", "Telegram chat id for health incident notifications")
	notifyMin := flag.String("notify-min-severity", "warn", "minimum health status to notify: warn|fail")
	token := flag.String("token", os.Getenv("OPS_API_TOKEN"), "api bearer token (or OPS_API_TOKEN env)")
	flag.Parse()

	store, err := newApprovalBackend(*pendingDriver, *pendingFile)
	if err != nil {
		panic(err)
	}

	_ = os.MkdirAll("audit", 0o755)
	s := &server{
		envFile:       *envFile,
		policyFile:    *policyFile,
		auditFile:     *auditFile,
		token:         strings.TrimSpace(*token),
		approvalStore: store,
		limiter:       newRateLimiter(*rateLimitWindow, *rateLimitMax),
		notifier:      notify.Build(*notifyWebhook, *slackWebhook, *telegramBotToken, *telegramChatID),
		notifyMin:     strings.ToLower(strings.TrimSpace(*notifyMin)),
		metrics: &apiMetrics{
			requestsTotal:    map[string]int64{},
			errorsTotal:      map[string]int64{},
			durationMsTotal:  map[string]float64{},
			actionsTotal:     map[string]int64{},
			actionsFailTotal: map[string]int64{},
		},
	}

	if *pendingTTL > 0 {
		if n, err := s.approvalStore.ExpirePendingOlderThan(*pendingTTL); err == nil && n > 0 {
			fmt.Printf("expired pending requests: %d\n", n)
		}
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/health/run", s.handleRunHealth)
	mux.HandleFunc("/actions/run", s.handleRunAction)
	mux.HandleFunc("/actions/request", s.handleRequestAction)
	mux.HandleFunc("/actions/approve", s.handleApproveAction)
	mux.HandleFunc("/actions/reject", s.handleRejectAction)
	mux.HandleFunc("/actions/pending", s.handlePendingActions)
	mux.HandleFunc("/actions/list", s.handleListActions)
	mux.HandleFunc("/audit/tail", s.handleTailAudit)
	mux.HandleFunc("/incidents/summary", s.handleIncidentSummary)
	mux.HandleFunc("/metrics", s.handleMetrics)
	mux.HandleFunc("/ready", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "service": "ops-api"})
	})

	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		sw := &statusWriter{ResponseWriter: w, status: 200}
		reqID := newID()
		sw.Header().Set("X-Request-ID", reqID)
		sw.Header().Set("Content-Type", "application/json")

		if !s.limiter.allow(clientIP(r)) {
			sw.WriteHeader(http.StatusTooManyRequests)
			_ = json.NewEncoder(sw).Encode(map[string]any{"error": "rate limit exceeded", "request_id": reqID})
			s.metricsRecord(r.URL.Path, sw.status, time.Since(start))
			return
		}

		if r.URL.Path != "/ready" && r.URL.Path != "/metrics" && !s.authorized(r) {
			sw.WriteHeader(http.StatusUnauthorized)
			_ = json.NewEncoder(sw).Encode(map[string]any{"error": "unauthorized", "request_id": reqID})
			s.metricsRecord(r.URL.Path, sw.status, time.Since(start))
			return
		}
		mux.ServeHTTP(sw, r)
		s.metricsRecord(r.URL.Path, sw.status, time.Since(start))
	})

	fmt.Println("ops-api listening on", *addr)
	fmt.Printf("approval store: driver=%s path=%s\n", *pendingDriver, *pendingFile)
	if s.token == "" {
		fmt.Println("warning: OPS API token is empty, endpoints are open (except /ready)")
	}
	if err := http.ListenAndServe(*addr, h); err != nil {
		panic(err)
	}
}

func newApprovalBackend(driver, path string) (approvalBackend, error) {
	d := strings.ToLower(strings.TrimSpace(driver))
	switch d {
	case "", "sqlite":
		return approval.SQLiteStore{Path: path}, nil
	case "json":
		return approval.Store{Path: path}, nil
	default:
		return nil, fmt.Errorf("unsupported pending-driver: %s", driver)
	}
}

func (s *server) authorized(r *http.Request) bool {
	if s.token == "" {
		return true
	}
	auth := strings.TrimSpace(r.Header.Get("Authorization"))
	if strings.HasPrefix(auth, "Bearer ") {
		return strings.TrimSpace(strings.TrimPrefix(auth, "Bearer ")) == s.token
	}
	return false
}

func (s *server) handleRunHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}
	envName := r.URL.Query().Get("env")
	if envName == "" {
		envName = "test"
	}

	cfg, err := config.LoadEnvironments(s.envFile)
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error":%q}`, err.Error()), http.StatusInternalServerError)
		return
	}
	env, ok := cfg.Environments[envName]
	if !ok {
		http.Error(w, `{"error":"env not found"}`, http.StatusNotFound)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	results := checks.NewRegistry(checks.CheckersForEnvironment(env)...).RunAll(ctx)
	policyCfg, _ := policy.Load(s.policyFile)
	recentAutoActions, _ := audit.CountRecentAutoActions(s.auditFile, envName, time.Now().UTC().Add(-time.Hour))
	report := incident.BuildReport("ops-api", envName, env, results, policyCfg, recentAutoActions)

	status := "ok"
	for _, rs := range results {
		sev := string(rs.Severity)
		if rs.Severity == checks.SeverityFail {
			status = "fail"
		} else if rs.Severity == checks.SeverityWarn && status != "fail" {
			status = "warn"
		}
		_ = audit.AppendJSONL(s.auditFile, audit.Event{Time: time.Now().UTC(), Actor: "ops-api", Action: "health_run", Env: envName, Target: envName + "/" + rs.Name, Status: sev, Message: rs.Code + ": " + rs.Message})
	}
	if s.notifier != nil && truthy(r.URL.Query().Get("notify")) && notify.ShouldNotify(report.Status, s.notifyMin) {
		if err := s.notifier.Notify(r.Context(), report); err != nil {
			_ = audit.AppendJSONL(s.auditFile, audit.Event{Time: time.Now().UTC(), Actor: "ops-api", Action: "notify", Env: envName, Status: "failed", Message: err.Error()})
		} else {
			_ = audit.AppendJSONL(s.auditFile, audit.Event{Time: time.Now().UTC(), Actor: "ops-api", Action: "notify", Env: envName, Status: "ok", Message: report.Summary})
		}
	}

	_ = json.NewEncoder(w).Encode(map[string]any{"env": envName, "status": status, "results": results, "suggestions": report.Suggestions, "summary": report.Summary})
}

func (s *server) handleRunAction(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}
	var req actionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, fmt.Sprintf(`{"error":%q}`, err.Error()), http.StatusBadRequest)
		return
	}
	if err := s.validateActionRequest(req); err != nil {
		http.Error(w, fmt.Sprintf(`{"error":%q}`, err.Error()), http.StatusBadRequest)
		return
	}
	if req.Actor == "" {
		req.Actor = "ops-api"
	}
	if req.Env == "" {
		req.Env = "test"
	}
	req.TargetHost = strings.TrimSpace(req.TargetHost)
	targetHost, err := s.resolveTargetHost(req.Env, req.TargetHost)
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error":%q}`, err.Error()), http.StatusBadRequest)
		return
	}

	cfg, err := policy.Load(s.policyFile)
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error":%q}`, err.Error()), http.StatusInternalServerError)
		return
	}
	recentAutoActions, err := audit.CountRecentAutoActions(s.auditFile, req.Env, time.Now().UTC().Add(-time.Hour))
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error":%q}`, err.Error()), http.StatusInternalServerError)
		return
	}
	decision := cfg.Evaluate(req.Action, req.Env, recentAutoActions)
	if !decision.Allowed {
		_ = audit.AppendJSONL(s.auditFile, audit.Event{Time: time.Now().UTC(), Actor: req.Actor, Action: req.Action, Env: req.Env, TargetHost: req.TargetHost, Target: req.TargetHost, Status: "denied", Message: decision.Reason})
		w.WriteHeader(http.StatusForbidden)
		_ = json.NewEncoder(w).Encode(actionResponse{Status: "denied", Message: decision.Reason})
		return
	}
	if decision.RequiresApproval && !req.Approved {
		_ = audit.AppendJSONL(s.auditFile, audit.Event{Time: time.Now().UTC(), Actor: req.Actor, Action: req.Action, Env: req.Env, TargetHost: req.TargetHost, Target: req.TargetHost, Status: "approval_required", Message: decision.Reason, RequiresOK: true})
		w.WriteHeader(http.StatusConflict)
		_ = json.NewEncoder(w).Encode(actionResponse{Status: "approval_required", Message: decision.Reason + " (use /actions/request + /actions/approve)"})
		return
	}

	res := runAction(req.Action, req.Args, req.TimeoutS, targetHost)
	s.actionRecord(req.Action, res.Err == nil)
	status := "ok"
	message := "action executed"
	if res.Err != nil {
		status = "failed"
		message = res.Err.Error()
	}
	_ = audit.AppendJSONL(s.auditFile, audit.Event{Time: time.Now().UTC(), Actor: req.Actor, Action: req.Action, Env: req.Env, TargetHost: req.TargetHost, Target: req.TargetHost, Status: status, Message: strings.TrimSpace(res.Output), RequiresOK: decision.RequiresApproval})

	if res.Err != nil {
		w.WriteHeader(http.StatusBadGateway)
	}
	_ = json.NewEncoder(w).Encode(actionResponse{Status: status, Message: message, ExitCode: res.ExitCode, Output: res.Output})
}

func (s *server) handleRequestAction(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}
	var req actionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, fmt.Sprintf(`{"error":%q}`, err.Error()), http.StatusBadRequest)
		return
	}
	if err := s.validateActionRequest(req); err != nil {
		http.Error(w, fmt.Sprintf(`{"error":%q}`, err.Error()), http.StatusBadRequest)
		return
	}
	if req.Actor == "" {
		req.Actor = "ops-api"
	}
	if req.Env == "" {
		req.Env = "test"
	}
	req.TargetHost = strings.TrimSpace(req.TargetHost)
	targetHost, err := s.resolveTargetHost(req.Env, req.TargetHost)
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error":%q}`, err.Error()), http.StatusBadRequest)
		return
	}
	cfg, err := policy.Load(s.policyFile)
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error":%q}`, err.Error()), http.StatusInternalServerError)
		return
	}
	recentAutoActions, err := audit.CountRecentAutoActions(s.auditFile, req.Env, time.Now().UTC().Add(-time.Hour))
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error":%q}`, err.Error()), http.StatusInternalServerError)
		return
	}
	decision := cfg.Evaluate(req.Action, req.Env, recentAutoActions)
	if !decision.Allowed {
		w.WriteHeader(http.StatusForbidden)
		_ = json.NewEncoder(w).Encode(requestActionResponse{Status: "denied", Message: decision.Reason})
		return
	}

	rid := newID()
	now := time.Now().UTC()
	entry := approval.Request{ID: rid, Action: req.Action, Env: req.Env, TargetHost: req.TargetHost, Args: req.Args, Actor: req.Actor, RequiresApproval: decision.RequiresApproval, Status: "pending", CreatedAt: now, UpdatedAt: now}

	s.mu.Lock()
	err = s.approvalStore.Create(entry)
	s.mu.Unlock()
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error":%q}`, err.Error()), http.StatusInternalServerError)
		return
	}
	_ = audit.AppendJSONL(s.auditFile, audit.Event{Time: now, Actor: req.Actor, Action: req.Action, Env: req.Env, TargetHost: req.TargetHost, Target: req.TargetHost, Status: "pending", Message: "action request created", RequiresOK: decision.RequiresApproval})

	if !decision.RequiresApproval {
		res := runAction(req.Action, req.Args, req.TimeoutS, targetHost)
		s.actionRecord(req.Action, res.Err == nil)
		newStatus := "executed"
		result := strings.TrimSpace(res.Output)
		if res.Err != nil {
			newStatus = "failed"
			if result == "" {
				result = res.Err.Error()
			}
		}
		s.mu.Lock()
		_, _ = s.approvalStore.Update(rid, func(r *approval.Request) error {
			r.Status = newStatus
			r.Result = result
			return nil
		})
		s.mu.Unlock()
		_ = audit.AppendJSONL(s.auditFile, audit.Event{Time: time.Now().UTC(), Actor: req.Actor, Action: req.Action, Env: req.Env, TargetHost: req.TargetHost, Target: req.TargetHost, Status: newStatus, Message: result})
		w.WriteHeader(http.StatusAccepted)
		_ = json.NewEncoder(w).Encode(requestActionResponse{Status: newStatus, Message: result, RequestID: rid})
		return
	}

	w.WriteHeader(http.StatusAccepted)
	_ = json.NewEncoder(w).Encode(requestActionResponse{Status: "pending", Message: "awaiting approval", RequestID: rid})
}

func (s *server) handleApproveAction(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}
	var req approveRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, fmt.Sprintf(`{"error":%q}`, err.Error()), http.StatusBadRequest)
		return
	}
	if strings.TrimSpace(req.RequestID) == "" {
		http.Error(w, `{"error":"request_id required"}`, http.StatusBadRequest)
		return
	}
	if req.Approver == "" {
		req.Approver = "ops-approver"
	}

	s.mu.Lock()
	entry, err := s.approvalStore.Update(req.RequestID, func(r *approval.Request) error {
		if r.Status != "pending" {
			return fmt.Errorf("request is not pending")
		}
		r.Status = "approved"
		r.Approver = req.Approver
		return nil
	})
	s.mu.Unlock()
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error":%q}`, err.Error()), http.StatusBadRequest)
		return
	}

	targetHost, err := s.resolveTargetHost(entry.Env, entry.TargetHost)
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error":%q}`, err.Error()), http.StatusBadRequest)
		return
	}
	res := runAction(entry.Action, entry.Args, req.TimeoutS, targetHost)
	s.actionRecord(entry.Action, res.Err == nil)
	finalStatus := "executed"
	result := strings.TrimSpace(res.Output)
	if res.Err != nil {
		finalStatus = "failed"
		if result == "" {
			result = res.Err.Error()
		}
	}

	s.mu.Lock()
	_, _ = s.approvalStore.Update(entry.ID, func(r *approval.Request) error {
		r.Status = finalStatus
		r.Result = result
		r.Approver = req.Approver
		return nil
	})
	s.mu.Unlock()

	_ = audit.AppendJSONL(s.auditFile, audit.Event{Time: time.Now().UTC(), Actor: req.Approver, Action: entry.Action, Env: entry.Env, TargetHost: entry.TargetHost, Target: entry.TargetHost, Status: finalStatus, Message: result, RequiresOK: entry.RequiresApproval})
	if res.Err != nil {
		w.WriteHeader(http.StatusBadGateway)
	}
	_ = json.NewEncoder(w).Encode(actionResponse{Status: finalStatus, Message: "approval processed", ExitCode: res.ExitCode, Output: res.Output})
}

func (s *server) handleRejectAction(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}
	var req rejectRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, fmt.Sprintf(`{"error":%q}`, err.Error()), http.StatusBadRequest)
		return
	}
	if strings.TrimSpace(req.RequestID) == "" {
		http.Error(w, `{"error":"request_id required"}`, http.StatusBadRequest)
		return
	}
	if req.Approver == "" {
		req.Approver = "ops-approver"
	}
	if strings.TrimSpace(req.Reason) == "" {
		req.Reason = "rejected by approver"
	}

	s.mu.Lock()
	entry, err := s.approvalStore.Update(req.RequestID, func(r *approval.Request) error {
		if r.Status != "pending" {
			return fmt.Errorf("request is not pending")
		}
		r.Status = "denied"
		r.Approver = req.Approver
		r.Result = req.Reason
		return nil
	})
	s.mu.Unlock()
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error":%q}`, err.Error()), http.StatusBadRequest)
		return
	}
	_ = audit.AppendJSONL(s.auditFile, audit.Event{Time: time.Now().UTC(), Actor: req.Approver, Action: entry.Action, Env: entry.Env, TargetHost: entry.TargetHost, Target: entry.TargetHost, Status: "denied", Message: req.Reason, RequiresOK: entry.RequiresApproval})
	_ = json.NewEncoder(w).Encode(actionResponse{Status: "denied", Message: "request rejected"})
}

func (s *server) handlePendingActions(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}
	limit := 50
	if v := r.URL.Query().Get("limit"); v != "" {
		fmt.Sscanf(v, "%d", &limit)
		if limit <= 0 || limit > 500 {
			limit = 50
		}
	}
	s.mu.Lock()
	items, err := s.approvalStore.ListPending(limit)
	s.mu.Unlock()
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error":%q}`, err.Error()), http.StatusInternalServerError)
		return
	}
	_ = json.NewEncoder(w).Encode(map[string]any{"count": len(items), "items": items})
}

func (s *server) handleListActions(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}
	status := strings.TrimSpace(r.URL.Query().Get("status"))
	if status == "" {
		status = "pending"
	}
	limit := 50
	if v := r.URL.Query().Get("limit"); v != "" {
		fmt.Sscanf(v, "%d", &limit)
		if limit <= 0 || limit > 500 {
			limit = 50
		}
	}
	cursor := strings.TrimSpace(r.URL.Query().Get("cursor"))

	s.mu.Lock()
	items, err := s.approvalStore.ListByStatus(status, 500)
	s.mu.Unlock()
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error":%q}`, err.Error()), http.StatusInternalServerError)
		return
	}

	start := 0
	if cursor != "" {
		for i, it := range items {
			if actionCursor(it) == cursor {
				start = i + 1
				break
			}
		}
	}
	if start > len(items) {
		start = len(items)
	}
	paged := items[start:]
	if len(paged) > limit {
		paged = paged[:limit]
	}
	nextCursor := ""
	if start+len(paged) < len(items) && len(paged) > 0 {
		nextCursor = actionCursor(paged[len(paged)-1])
	}

	_ = json.NewEncoder(w).Encode(map[string]any{"status": status, "count": len(paged), "items": paged, "next_cursor": nextCursor})
}

func (s *server) handleTailAudit(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}
	file := r.URL.Query().Get("file")
	resolvedFile, err := s.resolveAuditFile(file)
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error":%q}`, err.Error()), http.StatusBadRequest)
		return
	}
	limit := 50
	if v := r.URL.Query().Get("limit"); v != "" {
		fmt.Sscanf(v, "%d", &limit)
		if limit <= 0 || limit > 500 {
			limit = 50
		}
	}
	lines, err := tailLines(resolvedFile, limit)
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error":%q}`, err.Error()), http.StatusNotFound)
		return
	}
	_ = json.NewEncoder(w).Encode(map[string]any{"file": resolvedFile, "count": len(lines), "lines": lines})
}

func (s *server) handleIncidentSummary(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}
	window := 60
	if v := r.URL.Query().Get("minutes"); v != "" {
		fmt.Sscanf(v, "%d", &window)
		if window <= 0 || window > 24*60 {
			window = 60
		}
	}
	lines, err := tailLines(s.auditFile, 2000)
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error":%q}`, err.Error()), http.StatusNotFound)
		return
	}
	cutoff := time.Now().UTC().Add(-time.Duration(window) * time.Minute)
	byStatus := map[string]int{}
	targetCount := map[string]int{}
	total := 0
	for _, ln := range lines {
		var e audit.Event
		if err := json.Unmarshal([]byte(ln), &e); err != nil {
			continue
		}
		if e.Time.Before(cutoff) {
			continue
		}
		total++
		byStatus[e.Status]++
		if strings.TrimSpace(e.Target) != "" {
			targetCount[e.Target]++
		}
	}
	topTargets := topN(targetCount, 5)
	_ = json.NewEncoder(w).Encode(incidentSummary{WindowMinutes: window, Total: total, ByStatus: byStatus, TopTargets: topTargets})
}

func (s *server) handleMetrics(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "text/plain; version=0.0.4")
	s.metrics.mu.Lock()
	defer s.metrics.mu.Unlock()
	fmt.Fprintln(w, "# HELP ops_api_requests_total Total HTTP requests by path")
	fmt.Fprintln(w, "# TYPE ops_api_requests_total counter")
	for k, v := range s.metrics.requestsTotal {
		fmt.Fprintf(w, "ops_api_requests_total{path=%q} %d\n", k, v)
	}
	fmt.Fprintln(w, "# HELP ops_api_errors_total Total HTTP 5xx and 4xx responses by path")
	fmt.Fprintln(w, "# TYPE ops_api_errors_total counter")
	for k, v := range s.metrics.errorsTotal {
		fmt.Fprintf(w, "ops_api_errors_total{path=%q} %d\n", k, v)
	}
	fmt.Fprintln(w, "# HELP ops_api_request_duration_ms_total Total request duration in milliseconds by path")
	fmt.Fprintln(w, "# TYPE ops_api_request_duration_ms_total counter")
	for k, v := range s.metrics.durationMsTotal {
		fmt.Fprintf(w, "ops_api_request_duration_ms_total{path=%q} %.3f\n", k, v)
	}
	fmt.Fprintln(w, "# HELP ops_api_actions_total Total action executions by action")
	fmt.Fprintln(w, "# TYPE ops_api_actions_total counter")
	for k, v := range s.metrics.actionsTotal {
		fmt.Fprintf(w, "ops_api_actions_total{action=%q} %d\n", k, v)
	}
	fmt.Fprintln(w, "# HELP ops_api_action_failures_total Total failed action executions by action")
	fmt.Fprintln(w, "# TYPE ops_api_action_failures_total counter")
	for k, v := range s.metrics.actionsFailTotal {
		fmt.Fprintf(w, "ops_api_action_failures_total{action=%q} %d\n", k, v)
	}
}

func (s *server) metricsRecord(path string, status int, d time.Duration) {
	s.metrics.mu.Lock()
	defer s.metrics.mu.Unlock()
	s.metrics.requestsTotal[path]++
	if status >= 400 {
		s.metrics.errorsTotal[path]++
	}
	s.metrics.durationMsTotal[path] += float64(d.Milliseconds())
}

func (s *server) actionRecord(action string, ok bool) {
	s.metrics.mu.Lock()
	defer s.metrics.mu.Unlock()
	s.metrics.actionsTotal[action]++
	if !ok {
		s.metrics.actionsFailTotal[action]++
	}
}

func (s *server) validateActionRequest(req actionRequest) error {
	if strings.TrimSpace(req.Action) == "" {
		return fmt.Errorf("action required")
	}
	if env := strings.TrimSpace(req.Env); env != "" {
		if len(env) > 80 || strings.Contains(env, "\n") {
			return fmt.Errorf("invalid env")
		}
	}
	if targetHost := strings.TrimSpace(req.TargetHost); targetHost != "" {
		if len(targetHost) > 120 || strings.Contains(targetHost, "\n") {
			return fmt.Errorf("invalid target_host")
		}
	}
	if _, ok := actions.Lookup(req.Action); !ok {
		return fmt.Errorf("unsupported action")
	}
	return actions.ValidateArgs(req.Action, req.Args)
}

func actionCursor(r approval.Request) string {
	return r.CreatedAt.UTC().Format(time.RFC3339Nano) + "|" + r.ID
}

func clientIP(r *http.Request) string {
	xff := strings.TrimSpace(r.Header.Get("X-Forwarded-For"))
	if xff != "" {
		parts := strings.Split(xff, ",")
		if len(parts) > 0 {
			return strings.TrimSpace(parts[0])
		}
	}
	host := strings.TrimSpace(r.RemoteAddr)
	if i := strings.LastIndex(host, ":"); i > 0 {
		return host[:i]
	}
	if host == "" {
		return "unknown"
	}
	return host
}

func (s *server) resolveTargetHost(envName, targetHost string) (*config.Host, error) {
	targetHost = strings.TrimSpace(targetHost)
	if targetHost == "" {
		return nil, nil
	}
	cfg, err := config.LoadEnvironments(s.envFile)
	if err != nil {
		return nil, err
	}
	env, ok := cfg.Environment(envName)
	if !ok {
		return nil, fmt.Errorf("env not found: %s", envName)
	}
	host, ok := env.HostByName(targetHost)
	if !ok {
		return nil, fmt.Errorf("target_host %q not found in env %q", targetHost, envName)
	}
	return &host, nil
}

func (s *server) resolveAuditFile(name string) (string, error) {
	baseDir, err := filepath.Abs(filepath.Dir(s.auditFile))
	if err != nil {
		return "", err
	}
	canonicalBaseDir, err := filepath.EvalSymlinks(baseDir)
	if err == nil {
		baseDir = canonicalBaseDir
	}
	if strings.TrimSpace(name) == "" {
		resolvedDefault, err := filepath.Abs(s.auditFile)
		if err != nil {
			return "", err
		}
		if resolvedDefault, err = filepath.EvalSymlinks(resolvedDefault); err == nil {
			return resolvedDefault, nil
		}
		return resolvedDefault, nil
	}
	if filepath.Base(name) != name {
		return "", fmt.Errorf("file must be a basename within the audit directory")
	}
	if filepath.Ext(name) != ".jsonl" {
		return "", fmt.Errorf("file must end with .jsonl")
	}
	candidate := filepath.Join(baseDir, name)
	resolved, err := filepath.EvalSymlinks(candidate)
	if err != nil {
		if os.IsNotExist(err) {
			return "", err
		}
		resolved = candidate
	}
	resolved, err = filepath.Abs(resolved)
	if err != nil {
		return "", err
	}
	rel, err := filepath.Rel(baseDir, resolved)
	if err != nil {
		return "", err
	}
	if rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
		return "", fmt.Errorf("file escapes audit directory")
	}
	return resolved, nil
}

func tailLines(path string, limit int) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	lines := make([]string, 0, limit)
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		lines = append(lines, sc.Text())
		if len(lines) > limit {
			lines = lines[1:]
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return lines, nil
}

func topN(m map[string]int, n int) []string {
	type kv struct {
		K string
		V int
	}
	arr := make([]kv, 0, len(m))
	for k, v := range m {
		arr = append(arr, kv{k, v})
	}
	sort.Slice(arr, func(i, j int) bool { return arr[i].V > arr[j].V })
	if len(arr) > n {
		arr = arr[:n]
	}
	out := make([]string, 0, len(arr))
	for _, x := range arr {
		out = append(out, fmt.Sprintf("%s (%d)", x.K, x.V))
	}
	return out
}

func newID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return "req_" + hex.EncodeToString(b)
}

func truthy(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}

func runAction(action string, args []string, timeoutS int, host *config.Host) rbexec.Result {
	timeout := 30 * time.Second
	if timeoutS > 0 {
		timeout = time.Duration(timeoutS) * time.Second
	}
	return rbexec.RunAction(context.Background(), action, args, timeout, rbexec.Options{Host: host})
}
