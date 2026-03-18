package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/alan666gg/ops-agent/internal/audit"
	"github.com/alan666gg/ops-agent/internal/checks"
	"github.com/alan666gg/ops-agent/internal/config"
	"github.com/alan666gg/ops-agent/internal/incident"
	"github.com/alan666gg/ops-agent/internal/notify"
	"github.com/alan666gg/ops-agent/internal/policy"
)

func main() {
	envFile := flag.String("env-file", "configs/environments.yaml", "path to environments yaml")
	envName := flag.String("env", "test", "environment name")
	interval := flag.Duration("interval", 5*time.Minute, "check interval")
	auditFile := flag.String("audit", "audit/scheduler.jsonl", "audit jsonl output")
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

	cfg, err := config.LoadEnvironments(*envFile)
	if err != nil {
		fmt.Println("load env config error:", err)
		os.Exit(1)
	}
	env, ok := cfg.Environments[*envName]
	if !ok {
		fmt.Printf("env %q not found in %s\n", *envName, *envFile)
		os.Exit(1)
	}
	_ = os.MkdirAll("audit", 0o755)
	notifier := notify.Build(*notifyWebhook, *slackWebhook, *telegramBotToken, *telegramChatID)
	notifyCtl := notify.NewController(notifier, notify.NewSQLiteStore(*notifyStateFile), notify.ControllerOptions{
		MinSeverity:    *notifyMin,
		RepeatInterval: *notifyRepeat,
		NotifyRecovery: *notifyRecovery,
		TriggerAfter:   *notifyTriggerAfter,
		RecoveryAfter:  *notifyRecoveryAfter,
	})

	run := func() {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()

		results := checks.NewRegistry(checks.CheckersForEnvironment(env)...).RunAll(ctx)
		policyCfg, _ := policy.Load(*policyFile)
		recentAutoActions, _ := audit.CountRecentAutoActions(*auditFile, *envName, time.Now().UTC().Add(-time.Hour))
		report := incident.BuildReport("ops-scheduler", *envName, env, results, policyCfg, recentAutoActions)
		for _, r := range results {
			status := "ok"
			if r.Severity == checks.SeverityWarn {
				status = "warn"
			}
			if r.Severity == checks.SeverityFail {
				status = "fail"
			}
			fmt.Printf("[%s] %s %s\n", r.Name, r.Severity, r.Message)
			_ = audit.AppendJSONL(*auditFile, audit.Event{
				Time:    time.Now().UTC(),
				Actor:   "ops-scheduler",
				Action:  "health_cycle",
				Env:     *envName,
				Target:  *envName + "/" + r.Name,
				Status:  status,
				Message: r.Code + ": " + r.Message,
			})
		}
		if notifier != nil {
			decision, err := notifyCtl.Process(ctx, report)
			if err != nil {
				_ = audit.AppendJSONL(*auditFile, audit.Event{
					Time:    time.Now().UTC(),
					Actor:   "ops-scheduler",
					Action:  "notify",
					Env:     *envName,
					Status:  "failed",
					Message: err.Error(),
				})
			} else if decision.Send {
				_ = audit.AppendJSONL(*auditFile, audit.Event{
					Time:    time.Now().UTC(),
					Actor:   "ops-scheduler",
					Action:  "notify",
					Env:     *envName,
					Status:  "ok",
					Message: notify.DescribeDecision(decision),
				})
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
