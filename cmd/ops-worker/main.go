package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/alan666gg/ops-agent/internal/actions"
	"github.com/alan666gg/ops-agent/internal/audit"
	rbexec "github.com/alan666gg/ops-agent/internal/exec"
	"github.com/alan666gg/ops-agent/internal/policy"
)

func main() {
	action := flag.String("action", "", "action name, one of: "+strings.Join(actions.Names(), "|"))
	env := flag.String("env", "test", "environment name for policy evaluation")
	argsRaw := flag.String("args", "", "comma-separated args passed to runbook")
	policyFile := flag.String("policy", "configs/policies.yaml", "policy file path")
	auditFile := flag.String("audit", "audit/worker.jsonl", "audit output jsonl")
	actor := flag.String("actor", "ops-worker", "actor name")
	approved := flag.Bool("approved", false, "set true if human approval is granted")
	timeout := flag.Duration("timeout", 30*time.Second, "execution timeout")
	flag.Parse()

	if strings.TrimSpace(*action) == "" {
		fmt.Println("--action is required")
		os.Exit(1)
	}

	cfg, err := policy.Load(*policyFile)
	if err != nil {
		fmt.Println("load policy error:", err)
		os.Exit(1)
	}

	recentAutoActions, err := audit.CountRecentAutoActions(*auditFile, *env, time.Now().UTC().Add(-time.Hour))
	if err != nil {
		fmt.Println("count recent auto actions error:", err)
		os.Exit(1)
	}
	decision := cfg.Evaluate(*action, *env, recentAutoActions)
	if !decision.Allowed {
		emit(*auditFile, audit.Event{Time: time.Now().UTC(), Actor: *actor, Action: *action, Env: *env, Status: "denied", Message: decision.Reason})
		fmt.Println("denied:", decision.Reason)
		os.Exit(2)
	}
	if decision.RequiresApproval && !*approved {
		emit(*auditFile, audit.Event{Time: time.Now().UTC(), Actor: *actor, Action: *action, Env: *env, Status: "approval_required", Message: decision.Reason, RequiresOK: true})
		fmt.Println("approval required:", decision.Reason)
		os.Exit(3)
	}

	args := parseArgs(*argsRaw)
	if err := actions.ValidateArgs(*action, args); err != nil {
		emit(*auditFile, audit.Event{Time: time.Now().UTC(), Actor: *actor, Action: *action, Env: *env, Status: "denied", Message: err.Error()})
		fmt.Println("invalid action args:", err)
		os.Exit(2)
	}
	res := rbexec.RunAction(context.Background(), *action, args, *timeout)
	status := "ok"
	msg := res.Output
	if res.Err != nil {
		status = "failed"
		if msg == "" {
			msg = res.Err.Error()
		}
	}
	emit(*auditFile, audit.Event{Time: time.Now().UTC(), Actor: *actor, Action: *action, Env: *env, Status: status, Message: msg, RequiresOK: decision.RequiresApproval})

	if res.Output != "" {
		fmt.Println(res.Output)
	}
	if res.Err != nil {
		fmt.Printf("action failed (exit=%d): %v\n", res.ExitCode, res.Err)
		os.Exit(4)
	}
}

func parseArgs(raw string) []string {
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func emit(path string, evt audit.Event) {
	_ = os.MkdirAll("audit", 0o755)
	_ = audit.AppendJSONL(path, evt)
}
