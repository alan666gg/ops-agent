package main

import (
	"bufio"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/alan666gg/ops-agent/internal/audit"
	"github.com/alan666gg/ops-agent/internal/checks"
	"github.com/alan666gg/ops-agent/internal/config"
	rbexec "github.com/alan666gg/ops-agent/internal/exec"
	"github.com/alan666gg/ops-agent/internal/policy"
)

type server struct {
	envFile    string
	policyFile string
	auditFile  string
}

type actionRequest struct {
	Action   string   `json:"action"`
	Args     []string `json:"args"`
	Approved bool     `json:"approved"`
	Actor    string   `json:"actor"`
	TimeoutS int      `json:"timeout_seconds"`
}

type actionResponse struct {
	Status   string `json:"status"`
	Message  string `json:"message"`
	ExitCode int    `json:"exit_code,omitempty"`
	Output   string `json:"output,omitempty"`
}

func main() {
	addr := flag.String("addr", ":8090", "http listen addr")
	envFile := flag.String("env-file", "configs/environments.yaml", "path to environments yaml")
	policyFile := flag.String("policy", "configs/policies.yaml", "path to policy yaml")
	auditFile := flag.String("audit", "audit/api.jsonl", "audit output jsonl")
	flag.Parse()

	_ = os.MkdirAll("audit", 0o755)
	s := &server{envFile: *envFile, policyFile: *policyFile, auditFile: *auditFile}

	mux := http.NewServeMux()
	mux.HandleFunc("/health/run", s.handleRunHealth)
	mux.HandleFunc("/actions/run", s.handleRunAction)
	mux.HandleFunc("/audit/tail", s.handleTailAudit)
	mux.HandleFunc("/ready", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "service": "ops-api"})
	})

	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		mux.ServeHTTP(w, r)
	})

	fmt.Println("ops-api listening on", *addr)
	if err := http.ListenAndServe(*addr, h); err != nil {
		panic(err)
	}
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
		_ = audit.AppendJSONL(s.auditFile, audit.Event{
			Time:    time.Now().UTC(),
			Actor:   "ops-api",
			Action:  "health_run",
			Target:  envName + "/" + rs.Name,
			Status:  sev,
			Message: rs.Code + ": " + rs.Message,
		})
	}

	_ = json.NewEncoder(w).Encode(map[string]any{
		"env":     envName,
		"status":  status,
		"results": results,
	})
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
	if strings.TrimSpace(req.Action) == "" {
		http.Error(w, `{"error":"action required"}`, http.StatusBadRequest)
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
		_ = json.NewEncoder(w).Encode(actionResponse{Status: "approval_required", Message: "approval required"})
		return
	}

	timeout := 30 * time.Second
	if req.TimeoutS > 0 {
		timeout = time.Duration(req.TimeoutS) * time.Second
	}
	res := rbexec.RunAction(context.Background(), req.Action, req.Args, timeout)
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

	f, err := os.Open(file)
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error":%q}`, err.Error()), http.StatusNotFound)
		return
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
		http.Error(w, fmt.Sprintf(`{"error":%q}`, err.Error()), http.StatusInternalServerError)
		return
	}

	_ = json.NewEncoder(w).Encode(map[string]any{
		"file":  file,
		"count": len(lines),
		"lines": lines,
	})
}
