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
)

func main() {
	envFile := flag.String("env-file", "configs/environments.yaml", "path to environments yaml")
	envName := flag.String("env", "test", "environment name")
	interval := flag.Duration("interval", 5*time.Minute, "check interval")
	auditFile := flag.String("audit", "audit/scheduler.jsonl", "audit jsonl output")
	once := flag.Bool("once", false, "run one cycle and exit")
	flag.Parse()

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

	run := func() {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()

		results := checks.NewRegistry(checks.CheckersForEnvironment(env)...).RunAll(ctx)
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
