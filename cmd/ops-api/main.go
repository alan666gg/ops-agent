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
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/alan666gg/ops-agent/internal/approval"
	"github.com/alan666gg/ops-agent/internal/audit"
	"github.com/alan666gg/ops-agent/internal/checks"
	"github.com/alan666gg/ops-agent/internal/config"
	rbexec "github.com/alan666gg/ops-agent/internal/exec"
	"github.com/alan666gg/ops-agent/internal/policy"
)

type approvalBackend interface {
	Create(r approval.Request) error
	Update(id string, update func(*approval.Request) error) (approval.Request, error)
	ListPending(limit int) ([]approval.Request, error)
}

type server struct {
	envFile        string
	policyFile     string
	auditFile      string
	token          string
	allowedActions map[string]bool
	approvalStore  approvalBackend
	mu             sync.Mutex
}

type actionRequest struct {
	Action   string   `json:"action"`
	Args     []string `json:"args"`
	Approved bool     `json:"approved"`
	Actor    string   `json:"actor"`
	TimeoutS int      `json:"timeout_seconds"`
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
		allowedActions: map[string]bool{
			"check_host_health":    true,
			"check_service_health": true,
			"check_dependencies":   true,
			"restart_container":    true,
			"rollback_release":     true,
		},
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/health/run", s.handleRunHealth)
	mux.HandleFunc("/actions/run", s.handleRunAction)
	mux.HandleFunc("/actions/request", s.handleRequestAction)
	mux.HandleFunc("/actions/approve", s.handleApproveAction)
	mux.HandleFunc("/actions/reject", s.handleRejectAction)
	mux.HandleFunc("/actions/pending", s.handlePendingActions)
	mux.HandleFunc("/audit/tail", s.handleTailAudit)
	mux.HandleFunc("/incidents/summary", s.handleIncidentSummary)
	mux.HandleFunc("/ready", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "service": "ops-api"})
	})

	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path != "/ready" && !s.authorized(r) {
			w.WriteHeader(http.StatusUnauthorized)
			_ = json.NewEncoder(w).Encode(map[string]any{"error": "unauthorized"})
			return
		}
		mux.ServeHTTP(w, r)
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

	items := []checks.Checker{checks.HostChecker{}}
	for _, svc := range env.Services {
		if strings.TrimSpace(svc.HealthcheckURL) != "" {
			items = append(items, checks.HTTPChecker{TargetURL: svc.HealthcheckURL})
		}
	}
	for _, dep := range env.Dependencies {
		dep = strings.TrimSpace(dep)
		if strings.HasPrefix(dep, "tcp://") {
			target := strings.TrimPrefix(dep, "tcp://")
			parts := strings.Split(target, ":")
			if len(parts) == 2 {
				items = append(items, checks.TCPChecker{NameLabel: "dep_tcp", Host: parts[0], Port: parts[1]})
			}
		}
		if strings.HasPrefix(dep, "http://") || strings.HasPrefix(dep, "https://") {
			items = append(items, checks.HTTPChecker{TargetURL: dep})
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	results := checks.NewRegistry(items...).RunAll(ctx)

	status := "ok"
	for _, rs := range results {
		sev := string(rs.Severity)
		if rs.Severity == checks.SeverityFail {
			status = "fail"
		} else if rs.Severity == checks.SeverityWarn && status != "fail" {
			status = "warn"
		}
		_ = audit.AppendJSONL(s.auditFile, audit.Event{Time: time.Now().UTC(), Actor: "ops-api", Action: "health_run", Target: envName + "/" + rs.Name, Status: sev, Message: rs.Code + ": " + rs.Message})
	}

	_ = json.NewEncoder(w).Encode(map[string]any{"env": envName, "status": status, "results": results})
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

	cfg, err := policy.Load(s.policyFile)
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error":%q}`, err.Error()), http.StatusInternalServerError)
		return
	}
	allowed, requiresApproval := cfg.ActionAllowed(req.Action)
	if !allowed {
		_ = audit.AppendJSONL(s.auditFile, audit.Event{Time: time.Now().UTC(), Actor: req.Actor, Action: req.Action, Status: "denied", Message: "action denied by policy"})
		w.WriteHeader(http.StatusForbidden)
		_ = json.NewEncoder(w).Encode(actionResponse{Status: "denied", Message: "action denied by policy"})
		return
	}
	if requiresApproval && !req.Approved {
		_ = audit.AppendJSONL(s.auditFile, audit.Event{Time: time.Now().UTC(), Actor: req.Actor, Action: req.Action, Status: "approval_required", Message: "approval required", RequiresOK: true})
		w.WriteHeader(http.StatusConflict)
		_ = json.NewEncoder(w).Encode(actionResponse{Status: "approval_required", Message: "approval required (use /actions/request + /actions/approve)"})
		return
	}

	res := runAction(req.Action, req.Args, req.TimeoutS)
	status := "ok"
	message := "action executed"
	if res.Err != nil {
		status = "failed"
		message = res.Err.Error()
	}
	_ = audit.AppendJSONL(s.auditFile, audit.Event{Time: time.Now().UTC(), Actor: req.Actor, Action: req.Action, Status: status, Message: strings.TrimSpace(res.Output), RequiresOK: requiresApproval})

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
	cfg, err := policy.Load(s.policyFile)
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error":%q}`, err.Error()), http.StatusInternalServerError)
		return
	}
	allowed, requiresApproval := cfg.ActionAllowed(req.Action)
	if !allowed {
		w.WriteHeader(http.StatusForbidden)
		_ = json.NewEncoder(w).Encode(requestActionResponse{Status: "denied", Message: "action denied by policy"})
		return
	}

	rid := newID()
	now := time.Now().UTC()
	entry := approval.Request{ID: rid, Action: req.Action, Args: req.Args, Actor: req.Actor, RequiresApproval: requiresApproval, Status: "pending", CreatedAt: now, UpdatedAt: now}

	s.mu.Lock()
	err = s.approvalStore.Create(entry)
	s.mu.Unlock()
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error":%q}`, err.Error()), http.StatusInternalServerError)
		return
	}
	_ = audit.AppendJSONL(s.auditFile, audit.Event{Time: now, Actor: req.Actor, Action: req.Action, Status: "pending", Message: "action request created", RequiresOK: requiresApproval})

	if !requiresApproval {
		res := runAction(req.Action, req.Args, req.TimeoutS)
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
		_ = audit.AppendJSONL(s.auditFile, audit.Event{Time: time.Now().UTC(), Actor: req.Actor, Action: req.Action, Status: newStatus, Message: result})
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

	res := runAction(entry.Action, entry.Args, req.TimeoutS)
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

	_ = audit.AppendJSONL(s.auditFile, audit.Event{Time: time.Now().UTC(), Actor: req.Approver, Action: entry.Action, Status: finalStatus, Message: result, RequiresOK: entry.RequiresApproval})
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
	_ = audit.AppendJSONL(s.auditFile, audit.Event{Time: time.Now().UTC(), Actor: req.Approver, Action: entry.Action, Status: "denied", Message: req.Reason, RequiresOK: entry.RequiresApproval})
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

func (s *server) handleTailAudit(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}
	file := r.URL.Query().Get("file")
	if file == "" {
		file = s.auditFile
	}
	limit := 50
	if v := r.URL.Query().Get("limit"); v != "" {
		fmt.Sscanf(v, "%d", &limit)
		if limit <= 0 || limit > 500 {
			limit = 50
		}
	}
	lines, err := tailLines(file, limit)
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error":%q}`, err.Error()), http.StatusNotFound)
		return
	}
	_ = json.NewEncoder(w).Encode(map[string]any{"file": file, "count": len(lines), "lines": lines})
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

func (s *server) validateActionRequest(req actionRequest) error {
	if strings.TrimSpace(req.Action) == "" {
		return fmt.Errorf("action required")
	}
	if !s.allowedActions[req.Action] {
		return fmt.Errorf("action not in api allowlist")
	}
	if len(req.Args) > 8 {
		return fmt.Errorf("too many args")
	}
	for _, a := range req.Args {
		if len(a) > 300 || strings.Contains(a, "\n") {
			return fmt.Errorf("invalid arg")
		}
	}
	return nil
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

func runAction(action string, args []string, timeoutS int) rbexec.Result {
	timeout := 30 * time.Second
	if timeoutS > 0 {
		timeout = time.Duration(timeoutS) * time.Second
	}
	return rbexec.RunAction(context.Background(), action, args, timeout)
}
