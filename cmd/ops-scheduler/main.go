package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/alan666gg/ops-agent/internal/audit"
	"github.com/alan666gg/ops-agent/internal/checks"
	"github.com/alan666gg/ops-agent/internal/config"
	"github.com/alan666gg/ops-agent/internal/discovery"
	"github.com/alan666gg/ops-agent/internal/incident"
	"github.com/alan666gg/ops-agent/internal/notify"
	"github.com/alan666gg/ops-agent/internal/policy"
	"github.com/alan666gg/ops-agent/internal/slo"
)

func main() {
	envFile := flag.String("env-file", "configs/environments.yaml", "path to environments yaml")
	envName := flag.String("env", "test", "environment name")
	interval := flag.Duration("interval", 5*time.Minute, "check interval")
	auditFile := flag.String("audit", "audit/scheduler.jsonl", "audit jsonl output")
	auditDriver := flag.String("audit-driver", "jsonl", "audit store driver: jsonl|sqlite")
	incidentStateFile := flag.String("incident-state-file", "audit/incidents.db", "sqlite state file for open incidents and ownership")
	policyFile := flag.String("policy", "configs/policies.yaml", "policy file")
	notifyWebhook := flag.String("notify-webhook", "", "generic webhook URL for health incident notifications")
	slackWebhook := flag.String("notify-slack-webhook", "", "Slack incoming webhook URL for health incident notifications")
	telegramBotToken := flag.String("notify-telegram-bot-token", "", "Telegram bot token for health incident notifications")
	telegramChatID := flag.String("notify-telegram-chat-id", "", "Telegram chat id for health incident notifications")
	notifyMin := flag.String("notify-min-severity", "warn", "minimum health status to notify: warn|fail")
	notifyStateFile := flag.String("notify-state-file", "audit/notify-state.db", "notification dedupe state sqlite file")
	notifyRepeat := flag.Duration("notify-repeat", 30*time.Minute, "repeat identical incident notifications after this interval")
	notifyRecovery := flag.Bool("notify-recovery", true, "send notification when an incident recovers below the notify threshold")
	notifyTriggerAfter := flag.Int("notify-trigger-after", 1, "open an incident only after this many consecutive unhealthy cycles")
	notifyRecoveryAfter := flag.Int("notify-recovery-after", 1, "close an incident only after this many consecutive healthy cycles")
	notifyConfigFile := flag.String("notify-config", "", "notification routing config file (replaces direct notifier flags)")
	discoverInterval := flag.Duration("discover-interval", 0, "low-frequency auto-discovery interval; 0 disables periodic discovery")
	discoverTimeout := flag.Duration("discover-timeout", 30*time.Second, "ssh discovery timeout per host")
	discoverHealthPaths := flag.String("discover-health-paths", "/healthz,/health,/", "candidate HTTP paths used when auto-probing discovered services")
	discoverProbeTimeout := flag.Duration("discover-probe-timeout", 1500*time.Millisecond, "timeout for probing candidate healthcheck URLs during discovery apply")
	once := flag.Bool("once", false, "run one cycle and exit")
	flag.Parse()
	if err := notify.ValidateMinSeverity(*notifyMin); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	if err := notify.ValidateThreshold("notify-trigger-after", *notifyTriggerAfter); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	if err := notify.ValidateThreshold("notify-recovery-after", *notifyRecoveryAfter); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	if strings.TrimSpace(*notifyConfigFile) != "" && (strings.TrimSpace(*notifyWebhook) != "" || strings.TrimSpace(*slackWebhook) != "" || strings.TrimSpace(*telegramBotToken) != "" || strings.TrimSpace(*telegramChatID) != "") {
		fmt.Println("use either --notify-config or direct notifier flags, not both")
		os.Exit(1)
	}

	cfg, err := config.LoadEnvironments(*envFile)
	if err != nil {
		fmt.Println("load env config error:", err)
		os.Exit(1)
	}
	if _, ok := cfg.Environments[*envName]; !ok {
		fmt.Printf("env %q not found in %s\n", *envName, *envFile)
		os.Exit(1)
	}
	_ = os.MkdirAll("audit", 0o755)
	auditStore, err := audit.Open(*auditDriver, *auditFile)
	if err != nil {
		fmt.Println("open audit store error:", err)
		os.Exit(1)
	}
	incidentStore := incident.NewSQLiteStore(*incidentStateFile)
	notifier := notify.Build(*notifyWebhook, *slackWebhook, *telegramBotToken, *telegramChatID)
	var resolver notify.DeliveryResolver
	if strings.TrimSpace(*notifyConfigFile) != "" {
		routingCfg, err := notify.LoadRouting(*notifyConfigFile)
		if err != nil {
			fmt.Println("notification config invalid:", err)
			os.Exit(1)
		}
		resolver, err = routingCfg.BuildResolver()
		if err != nil {
			fmt.Println("notification config invalid:", err)
			os.Exit(1)
		}
	}
	notifyCtl := notify.NewController(notifier, notify.NewSQLiteStore(*notifyStateFile), notify.ControllerOptions{
		MinSeverity:    *notifyMin,
		RepeatInterval: *notifyRepeat,
		NotifyRecovery: *notifyRecovery,
		TriggerAfter:   *notifyTriggerAfter,
		RecoveryAfter:  *notifyRecoveryAfter,
		Resolver:       resolver,
	})
	var lastDiscovery time.Time

	run := func() {
		cfg, err := config.LoadEnvironments(*envFile)
		if err != nil {
			fmt.Printf("load env config error: %v\n", err)
			_ = auditStore.Append(audit.Event{
				Time:    time.Now().UTC(),
				Actor:   "ops-scheduler",
				Action:  "config_reload",
				Project: cfg.ProjectForEnv(*envName),
				Env:     *envName,
				Status:  "failed",
				Message: err.Error(),
			})
			return
		}
		env, ok := cfg.Environments[*envName]
		if !ok {
			msg := fmt.Sprintf("env %q not found in %s", *envName, *envFile)
			fmt.Println(msg)
			_ = auditStore.Append(audit.Event{
				Time:    time.Now().UTC(),
				Actor:   "ops-scheduler",
				Action:  "config_reload",
				Project: cfg.ProjectForEnv(*envName),
				Env:     *envName,
				Status:  "failed",
				Message: msg,
			})
			return
		}
		project := env.ProjectName()
		runTimeout := 20 * time.Second
		if *discoverInterval > 0 && len(env.Hosts) > 0 {
			runTimeout += time.Duration(len(env.Hosts)) * *discoverTimeout
		}
		ctx, cancel := context.WithTimeout(context.Background(), runTimeout)
		defer cancel()

		if shouldRunDiscovery(lastDiscovery, *discoverInterval) {
			discoveredEnv, summary := runDiscoveryCycle(ctx, auditStore, *envName, env, discovery.ApplyOptions{
				HealthPaths:  splitCSV(*discoverHealthPaths),
				ProbeTimeout: *discoverProbeTimeout,
			}, *discoverTimeout)
			lastDiscovery = time.Now().UTC()
			if summary.Attempted > 0 {
				evt := audit.Event{
					Time:    time.Now().UTC(),
					Actor:   "ops-scheduler",
					Action:  "discovery_cycle",
					Project: project,
					Env:     *envName,
					Status:  "ok",
					Message: fmt.Sprintf("attempted=%d failed=%d added=%d updated=%d skipped=%d", summary.Attempted, summary.Failed, summary.Added, summary.Updated, summary.Skipped),
				}
				if summary.Failed > 0 {
					evt.Status = "warn"
				}
				_ = auditStore.Append(evt)
			}
			if summary.Changed {
				cfg.Environments[*envName] = discoveredEnv
				if err := config.SaveEnvironments(*envFile, cfg); err != nil {
					fmt.Printf("save env config error: %v\n", err)
					_ = auditStore.Append(audit.Event{
						Time:    time.Now().UTC(),
						Actor:   "ops-scheduler",
						Action:  "discovery_apply",
						Project: project,
						Env:     *envName,
						Status:  "failed",
						Message: err.Error(),
					})
				} else {
					env = discoveredEnv
					project = env.ProjectName()
					_ = auditStore.Append(audit.Event{
						Time:    time.Now().UTC(),
						Actor:   "ops-scheduler",
						Action:  "discovery_apply",
						Project: project,
						Env:     *envName,
						Status:  "ok",
						Message: fmt.Sprintf("applied added=%d updated=%d skipped=%d", summary.Added, summary.Updated, summary.Skipped),
					})
				}
			}
		}

		results := checks.NewRegistry(checks.CheckersForEnvironment(env)...).RunAll(ctx)
		for _, r := range results {
			fmt.Printf("[%s] %s %s\n", r.Name, r.Severity, r.Message)
			_ = auditStore.Append(audit.Event{
				Time:    time.Now().UTC(),
				Actor:   "ops-scheduler",
				Action:  "health_cycle",
				Project: project,
				Env:     *envName,
				Target:  *envName + "/" + r.Name,
				Status:  schedulerResultStatus(r),
				Message: r.Code + ": " + r.Message,
			})
		}
		if sloResults, err := (slo.Evaluator{}).EvaluateAvailabilityStore(auditStore, project, *envName, env); err == nil {
			results = append(results, sloResults...)
			for _, r := range sloResults {
				fmt.Printf("[%s] %s %s\n", r.Name, r.Severity, r.Message)
				_ = auditStore.Append(audit.Event{
					Time:    time.Now().UTC(),
					Actor:   "ops-scheduler",
					Action:  "slo_eval",
					Project: project,
					Env:     *envName,
					Target:  *envName + "/" + r.Name,
					Status:  schedulerResultStatus(r),
					Message: r.Code + ": " + r.Message,
				})
			}
		} else {
			_ = auditStore.Append(audit.Event{
				Time:    time.Now().UTC(),
				Actor:   "ops-scheduler",
				Action:  "slo_eval",
				Project: project,
				Env:     *envName,
				Status:  "failed",
				Message: err.Error(),
			})
		}
		policyCfg, _ := policy.Load(*policyFile)
		recentAutoActions, _ := auditStore.CountRecentAutoActions(project, *envName, time.Now().UTC().Add(-time.Hour))
		report := incident.BuildReport("ops-scheduler", *envName, env, results, policyCfg, recentAutoActions)
		record, err := syncIncident(incidentStore, report)
		if err != nil {
			_ = auditStore.Append(audit.Event{
				Time:    time.Now().UTC(),
				Actor:   "ops-scheduler",
				Action:  "incident_sync",
				Project: project,
				Env:     *envName,
				Status:  "failed",
				Message: err.Error(),
			})
		}
		if notifyCtl.Enabled() {
			if suppressAcknowledged(record, report) {
				_ = auditStore.Append(audit.Event{
					Time:    time.Now().UTC(),
					Actor:   "ops-scheduler",
					Action:  "notify",
					Project: project,
					Env:     *envName,
					Status:  "suppressed",
					Message: "incident acknowledged by " + record.AcknowledgedBy,
				})
			} else {
				decision, err := notifyCtl.Process(ctx, report)
				if err != nil {
					_ = auditStore.Append(audit.Event{
						Time:    time.Now().UTC(),
						Actor:   "ops-scheduler",
						Action:  "notify",
						Project: project,
						Env:     *envName,
						Status:  "failed",
						Message: err.Error(),
					})
				} else if decision.Send {
					_ = auditStore.Append(audit.Event{
						Time:    time.Now().UTC(),
						Actor:   "ops-scheduler",
						Action:  "notify",
						Project: project,
						Env:     *envName,
						Status:  "ok",
						Message: notify.DescribeDecision(decision),
					})
				}
			}
		}
	}

	run()
	if *once {
		return
	}
	t := time.NewTicker(*interval)
	defer t.Stop()
	for range t.C {
		run()
	}
}

type discoverySummary struct {
	Attempted int
	Failed    int
	Added     int
	Updated   int
	Skipped   int
	Changed   bool
}

func runDiscoveryCycle(ctx context.Context, auditStore audit.Store, envName string, env config.Environment, opts discovery.ApplyOptions, timeout time.Duration) (config.Environment, discoverySummary) {
	updatedEnv := env
	var summary discoverySummary
	project := env.ProjectName()
	for _, host := range env.Hosts {
		summary.Attempted++
		report, err := discovery.Discover(ctx, host, timeout, nil)
		if err != nil {
			summary.Failed++
			_ = auditStore.Append(audit.Event{
				Time:       time.Now().UTC(),
				Actor:      "ops-scheduler",
				Action:     "discover_host",
				Project:    project,
				Env:        envName,
				TargetHost: host.Name,
				Status:     "failed",
				Message:    err.Error(),
			})
			continue
		}
		result := discovery.ApplyReport(ctx, &updatedEnv, report, opts)
		summary.Added += len(result.Added)
		summary.Updated += len(result.Updated)
		summary.Skipped += len(result.Skipped)
		if len(result.Added) > 0 || len(result.Updated) > 0 {
			summary.Changed = true
		}
		_ = auditStore.Append(audit.Event{
			Time:       time.Now().UTC(),
			Actor:      "ops-scheduler",
			Action:     "discover_host",
			Project:    project,
			Env:        envName,
			TargetHost: host.Name,
			Status:     "ok",
			Message:    fmt.Sprintf("suggested=%d added=%d updated=%d skipped=%d", len(report.SuggestedService), len(result.Added), len(result.Updated), len(result.Skipped)),
		})
	}
	return updatedEnv, summary
}

func shouldRunDiscovery(last time.Time, interval time.Duration) bool {
	if interval <= 0 {
		return false
	}
	if last.IsZero() {
		return true
	}
	return time.Since(last) >= interval
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

func schedulerResultStatus(r checks.Result) string {
	switch r.Severity {
	case checks.SeverityWarn:
		return "warn"
	case checks.SeverityFail:
		return "fail"
	default:
		return "ok"
	}
}

func syncIncident(store incident.Store, report incident.Report) (incident.Record, error) {
	if store == nil {
		return incident.Record{}, nil
	}
	return store.SyncReport(report, time.Now().UTC())
}

func suppressAcknowledged(rec incident.Record, report incident.Report) bool {
	if !incident.IsActionableStatus(report.Status) {
		return false
	}
	if !rec.Open || !rec.Acknowledged {
		return false
	}
	return strings.TrimSpace(rec.Fingerprint) == strings.TrimSpace(report.Fingerprint)
}
