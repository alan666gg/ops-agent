package exec

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

type Result struct {
	ExitCode int
	Output   string
	Err      error
}

var actionToCmd = map[string][]string{
	"check_host_health":    {"bash", "runbooks/check_host_health.sh"},
	"check_service_health": {"bash", "runbooks/check_service_health.sh"},
	"check_dependencies":   {"bash", "runbooks/check_dependencies.sh"},
	"restart_container":    {"bash", "runbooks/restart_container.sh"},
	"rollback_release":     {"bash", "runbooks/rollback_release.sh"},
}

func RunAction(ctx context.Context, action string, args []string, timeout time.Duration) Result {
	base, ok := actionToCmd[action]
	if !ok {
		return Result{ExitCode: 127, Err: fmt.Errorf("unknown action: %s", action)}
	}
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	cctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	cmdArgs := append(append([]string{}, base...), args...)
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
