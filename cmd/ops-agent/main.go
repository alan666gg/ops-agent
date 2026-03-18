package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/alan666gg/ops-agent/internal/actions"
	"github.com/alan666gg/ops-agent/internal/audit"
	"github.com/alan666gg/ops-agent/internal/chatops"
	"github.com/alan666gg/ops-agent/internal/checks"
	"github.com/alan666gg/ops-agent/internal/config"
	"github.com/alan666gg/ops-agent/internal/discovery"
	"github.com/alan666gg/ops-agent/internal/notify"
	"github.com/alan666gg/ops-agent/internal/policy"
	"gopkg.in/yaml.v3"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(1)
	}

	switch os.Args[1] {
	case "health":
		runHealth(os.Args[2:])
	case "policy":
		runPolicy(os.Args[2:])
	case "discover":
		runDiscover(os.Args[2:])
	case "validate":
		runValidate(os.Args[2:])
	default:
		usage()
		os.Exit(1)
	}
}

func usage() {
	fmt.Println("ops-agent commands:")
	fmt.Println("  health --url http://127.0.0.1:8080/ --dep redis:127.0.0.1:6379")
	fmt.Println("  policy --action <" + strings.Join(actions.Names(), "|") + "> --env test --policy configs/policies.yaml --audit audit.jsonl")
	fmt.Println("  discover --env-file configs/environments.yaml --env test --host test-app-1 --format yaml")
	fmt.Println("  validate --env-file configs/environments.yaml --policy configs/policies.yaml --notify-config configs/notifications.yaml --chatops-config configs/chatops.yaml")
}

func runHealth(args []string) {
	fs := flag.NewFlagSet("health", flag.ExitOnError)
	url := fs.String("url", "", "http endpoint to check")
	dep := fs.String("dep", "", "dependency in format name:host:port, comma-separated")
	_ = fs.Parse(args)

	items := []checks.Checker{checks.HostChecker{}}
	if *url != "" {
		items = append(items, checks.HTTPChecker{TargetURL: *url})
	}
	for _, d := range splitCSV(*dep) {
		p := strings.Split(d, ":")
		if len(p) != 3 {
			continue
		}
		items = append(items, checks.TCPChecker{NameLabel: p[0], Host: p[1], Port: p[2]})
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	results := checks.NewRegistry(items...).RunAll(ctx)
	failed := false
	for _, r := range results {
		fmt.Printf("[%s] code=%s severity=%s msg=%s\n", r.Name, r.Code, r.Severity, r.Message)
		if r.Severity == checks.SeverityFail {
			failed = true
		}
	}
	if failed {
		os.Exit(2)
	}
}

func runPolicy(args []string) {
	fs := flag.NewFlagSet("policy", flag.ExitOnError)
	action := fs.String("action", "", "action name")
	env := fs.String("env", "test", "environment name")
	policyFile := fs.String("policy", "configs/policies.yaml", "policy file")
	auditFile := fs.String("audit", "audit/events.jsonl", "audit jsonl file")
	actor := fs.String("actor", "ops-agent", "actor name")
	_ = fs.Parse(args)

	if *action == "" {
		fmt.Println("action is required")
		os.Exit(1)
	}

	cfg, err := policy.Load(*policyFile)
	if err != nil {
		fmt.Println("load policy error:", err)
		os.Exit(1)
	}

	recentAutoActions, err := audit.CountRecentAutoActions(*auditFile, *env, time.Now().UTC().Add(-time.Hour))
	if err != nil {
		fmt.Println("count audit error:", err)
		os.Exit(1)
	}
	decision := cfg.Evaluate(*action, *env, recentAutoActions)
	status := "allowed"
	msg := decision.Reason
	requires := decision.RequiresApproval
	if !decision.Allowed {
		status = "denied"
	} else if decision.RequiresApproval {
		status = "approval_required"
	}

	fmt.Printf("policy result: %s (%s)\n", status, msg)
	_ = os.MkdirAll("audit", 0o755)
	_ = audit.AppendJSONL(*auditFile, audit.Event{
		Time:       time.Now().UTC(),
		Actor:      *actor,
		Action:     *action,
		Env:        *env,
		Status:     status,
		Message:    msg,
		RequiresOK: requires,
	})

	if status != "allowed" {
		os.Exit(3)
	}
}

func runValidate(args []string) {
	fs := flag.NewFlagSet("validate", flag.ExitOnError)
	envFile := fs.String("env-file", "configs/environments.yaml", "environment config file")
	policyFile := fs.String("policy", "configs/policies.yaml", "policy file")
	notifyConfigFile := fs.String("notify-config", "", "notification routing config file")
	chatopsConfigFile := fs.String("chatops-config", "", "chatops security config file")
	_ = fs.Parse(args)

	envCfg, err := config.LoadEnvironments(*envFile)
	if err != nil {
		fmt.Println("environment config invalid:", err)
		os.Exit(1)
	}
	policyCfg, err := policy.Load(*policyFile)
	if err != nil {
		fmt.Println("policy config invalid:", err)
		os.Exit(1)
	}

	fmt.Printf("environment config valid: %d environments\n", len(envCfg.Environments))
	fmt.Printf("policy config valid: %d allowed, %d approval-required actions\n",
		len(policyCfg.Policies.AutoActions.Allowed),
		len(policyCfg.Policies.AutoActions.RequireApproval),
	)
	if strings.TrimSpace(*notifyConfigFile) != "" {
		notifyCfg, err := notify.LoadRouting(*notifyConfigFile)
		if err != nil {
			fmt.Println("notification config invalid:", err)
			os.Exit(1)
		}
		fmt.Printf("notification config valid: %d receivers, %d routes, %d silences, %d maintenance windows\n",
			len(notifyCfg.Receivers),
			len(notifyCfg.Routes),
			len(notifyCfg.Silences),
			len(notifyCfg.MaintenanceWindows),
		)
	}
	if strings.TrimSpace(*chatopsConfigFile) != "" {
		chatCfg, err := chatops.LoadSecurityConfig(*chatopsConfigFile)
		if err != nil {
			fmt.Println("chatops config invalid:", err)
			os.Exit(1)
		}
		fmt.Printf("chatops config valid: %d users, %d deny patterns, max_input_chars=%d\n",
			len(chatCfg.Users),
			len(chatCfg.DenyPatterns),
			chatCfg.MaxInputChars,
		)
	}
}

func runDiscover(args []string) {
	fs := flag.NewFlagSet("discover", flag.ExitOnError)
	envFile := fs.String("env-file", "configs/environments.yaml", "environment config file")
	envName := fs.String("env", "test", "environment name")
	hostName := fs.String("host", "", "host name declared in the environment config")
	format := fs.String("format", "yaml", "output format: yaml|json")
	timeout := fs.Duration("timeout", 30*time.Second, "ssh discovery timeout")
	outPath := fs.String("out", "", "optional output file path (defaults to stdout)")
	_ = fs.Parse(args)

	if strings.TrimSpace(*hostName) == "" {
		fmt.Println("host is required")
		os.Exit(1)
	}
	cfg, err := config.LoadEnvironments(*envFile)
	if err != nil {
		fmt.Println("environment config invalid:", err)
		os.Exit(1)
	}
	env, ok := cfg.Environment(*envName)
	if !ok {
		fmt.Printf("env %q not found in %s\n", *envName, *envFile)
		os.Exit(1)
	}
	host, ok := env.HostByName(*hostName)
	if !ok {
		fmt.Printf("host %q not found in env %q\n", *hostName, *envName)
		os.Exit(1)
	}

	report, err := discovery.Discover(context.Background(), host, *timeout, nil)
	if err != nil {
		fmt.Println("discovery failed:", err)
		os.Exit(1)
	}
	var payload []byte
	switch strings.ToLower(strings.TrimSpace(*format)) {
	case "json":
		payload, err = json.MarshalIndent(report, "", "  ")
	case "yaml", "yml":
		payload, err = yaml.Marshal(report)
	default:
		fmt.Println("format must be yaml or json")
		os.Exit(1)
	}
	if err != nil {
		fmt.Println("encode discovery report error:", err)
		os.Exit(1)
	}
	if strings.TrimSpace(*outPath) != "" {
		if err := os.MkdirAll(filepath.Dir(*outPath), 0o755); err != nil {
			fmt.Println("create discovery output dir error:", err)
			os.Exit(1)
		}
		if err := os.WriteFile(*outPath, payload, 0o644); err != nil {
			fmt.Println("write discovery report error:", err)
			os.Exit(1)
		}
		fmt.Printf("discovery report written to %s\n", *outPath)
		return
	}
	fmt.Println(string(payload))
}

func splitCSV(s string) []string {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	raw := strings.Split(s, ",")
	out := make([]string, 0, len(raw))
	for _, v := range raw {
		v = strings.TrimSpace(v)
		if v != "" {
			out = append(out, v)
		}
	}
	return out
}
