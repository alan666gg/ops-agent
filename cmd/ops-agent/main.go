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
	promapi "github.com/alan666gg/ops-agent/internal/prometheus"
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
	case "promql":
		runPromQL(os.Args[2:])
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
	fmt.Println("  discover --env-file configs/environments.yaml --env test --host test-app-1 --format yaml --apply")
	fmt.Println("  promql --env-file configs/environments.yaml --env test --query 'up' --minutes 30")
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
	envFile := fs.String("env-file", "configs/environments.yaml", "environment config file")
	policyFile := fs.String("policy", "configs/policies.yaml", "policy file")
	auditFile := fs.String("audit", "audit/events.jsonl", "audit jsonl file")
	auditDriver := fs.String("audit-driver", "jsonl", "audit store driver: jsonl|sqlite")
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
	auditStore, err := audit.Open(*auditDriver, *auditFile)
	if err != nil {
		fmt.Println("open audit store error:", err)
		os.Exit(1)
	}
	project := "default"
	if envCfg, err := config.LoadEnvironments(*envFile); err == nil {
		project = envCfg.ProjectForEnv(*env)
	}

	recentAutoActions, err := auditStore.CountRecentAutoActions(project, *env, time.Now().UTC().Add(-time.Hour))
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
	_ = auditStore.Append(audit.Event{
		Time:       time.Now().UTC(),
		Actor:      *actor,
		Action:     *action,
		Project:    project,
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
	apply := fs.Bool("apply", false, "merge discovered services into the selected environment config")
	healthPaths := fs.String("health-paths", "/healthz,/health,/", "candidate HTTP paths used when auto-probing discovered services")
	probeTimeout := fs.Duration("probe-timeout", 1500*time.Millisecond, "timeout for probing candidate healthcheck URLs during --apply")
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
	if *apply {
		envCopy := env
		result := discovery.ApplyReport(context.Background(), &envCopy, report, discovery.ApplyOptions{
			HealthPaths:  splitCSV(*healthPaths),
			ProbeTimeout: *probeTimeout,
		})
		cfg.Environments[*envName] = envCopy
		if err := config.SaveEnvironments(*envFile, cfg); err != nil {
			fmt.Println("save environment config error:", err)
			os.Exit(1)
		}
		fmt.Printf("applied discovery to %s env=%s host=%s: added=%d updated=%d skipped=%d\n", *envFile, *envName, host.Name, len(result.Added), len(result.Updated), len(result.Skipped))
		for _, svc := range result.Added {
			fmt.Printf("  added service %s type=%s container=%s systemd=%s port=%d health=%s\n", svc.Name, defaultString(svc.Type, "(unknown)"), defaultString(svc.ContainerName, "-"), defaultString(svc.SystemdUnit, "-"), svc.ListenerPort, defaultString(svc.HealthcheckURL, "(none)"))
		}
		for _, svc := range result.Updated {
			fmt.Printf("  updated service %s type=%s systemd=%s port=%d health=%s\n", svc.Name, defaultString(svc.Type, "(unknown)"), defaultString(svc.SystemdUnit, "-"), svc.ListenerPort, defaultString(svc.HealthcheckURL, "(none)"))
		}
		if len(result.Skipped) > 0 {
			fmt.Printf("  skipped existing candidates: %s\n", strings.Join(result.Skipped, ", "))
		}
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

func runPromQL(args []string) {
	fs := flag.NewFlagSet("promql", flag.ExitOnError)
	envFile := fs.String("env-file", "configs/environments.yaml", "environment config file")
	envName := fs.String("env", "test", "environment name")
	query := fs.String("query", "", "PromQL expression")
	minutes := fs.Int("minutes", 0, "range window in minutes; 0 means instant query")
	step := fs.Duration("step", 0, "range query step duration; auto-selected when omitted")
	format := fs.String("format", "text", "output format: text|json|yaml")
	_ = fs.Parse(args)

	if strings.TrimSpace(*query) == "" {
		fmt.Println("query is required")
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
	promCfg := env.Prometheus.WithDefaults()
	if !promCfg.Enabled() {
		fmt.Printf("env %q has no prometheus config\n", *envName)
		os.Exit(1)
	}
	token := ""
	if name := strings.TrimSpace(promCfg.BearerTokenEnv); name != "" {
		token = strings.TrimSpace(os.Getenv(name))
		if token == "" {
			fmt.Printf("prometheus bearer token env %q is empty\n", name)
			os.Exit(1)
		}
	}
	client := promapi.Client{
		BaseURL:     promCfg.BaseURL,
		BearerToken: token,
	}
	ctx, cancel := context.WithTimeout(context.Background(), promCfg.Timeout)
	defer cancel()

	var out promapi.QueryResponse
	if *minutes > 0 {
		if *step <= 0 {
			*step = promapi.AutoStep(time.Duration(*minutes) * time.Minute)
		}
		end := time.Now().UTC()
		start := end.Add(-time.Duration(*minutes) * time.Minute)
		out, err = client.QueryRange(ctx, *query, start, end, *step)
	} else {
		out, err = client.QueryInstant(ctx, *query, time.Now().UTC())
	}
	if err != nil {
		fmt.Println("prometheus query failed:", err)
		os.Exit(1)
	}

	switch strings.ToLower(strings.TrimSpace(*format)) {
	case "text":
		fmt.Println(out.Summary)
	case "json":
		b, err := json.MarshalIndent(out, "", "  ")
		if err != nil {
			fmt.Println("encode query result error:", err)
			os.Exit(1)
		}
		fmt.Println(string(b))
	case "yaml", "yml":
		b, err := yaml.Marshal(out)
		if err != nil {
			fmt.Println("encode query result error:", err)
			os.Exit(1)
		}
		fmt.Println(string(b))
	default:
		fmt.Println("format must be text, json, or yaml")
		os.Exit(1)
	}
}

func defaultString(v, fallback string) string {
	if strings.TrimSpace(v) == "" {
		return fallback
	}
	return v
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
