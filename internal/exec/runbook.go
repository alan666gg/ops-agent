package exec

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"github.com/alan666gg/ops-agent/internal/actions"
)

type Result struct {
	ExitCode int
	Output   string
	Err      error
}

func RunAction(ctx context.Context, action string, args []string, timeout time.Duration) Result {
	spec, ok := actions.Lookup(action)
	if !ok {
		return Result{ExitCode: 127, Err: fmt.Errorf("unknown action: %s", action)}
	}
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	cctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	cmdArgs := append(append([]string{}, spec.Runbook...), args...)
	cmd := exec.CommandContext(cctx, cmdArgs[0], cmdArgs[1:]...)
	out, err := cmd.CombinedOutput()

	exitCode := 0
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			exitCode = ee.ExitCode()
		} else {
			exitCode = 1
		}
	}
	return Result{ExitCode: exitCode, Output: strings.TrimSpace(string(out)), Err: err}
}
