package exec

import (
	"bytes"
	"context"
	"fmt"
	"os"
	osexec "os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/alan666gg/ops-agent/internal/actions"
	"github.com/alan666gg/ops-agent/internal/config"
)

type Options struct {
	Host *config.Host
}

type Result struct {
	ExitCode int
	Output   string
	Err      error
}

func RunAction(ctx context.Context, action string, args []string, timeout time.Duration, opts Options) Result {
	spec, ok := actions.Lookup(action)
	if !ok {
		return Result{ExitCode: 127, Err: fmt.Errorf("unknown action: %s", action)}
	}
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	cctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	name, cmdArgs, stdin, err := buildInvocation(spec, args, opts)
	if err != nil {
		return Result{ExitCode: 1, Err: err}
	}
	cmd := osexec.CommandContext(cctx, name, cmdArgs...)
	if stdin != nil {
		cmd.Stdin = bytes.NewReader(stdin)
	}
	out, err := cmd.CombinedOutput()

	exitCode := 0
	if err != nil {
		if ee, ok := err.(*osexec.ExitError); ok {
			exitCode = ee.ExitCode()
		} else {
			exitCode = 1
		}
	}
	return Result{ExitCode: exitCode, Output: strings.TrimSpace(string(out)), Err: err}
}

func buildInvocation(spec actions.Spec, args []string, opts Options) (string, []string, []byte, error) {
	if opts.Host == nil {
		if len(spec.Runbook) == 0 {
			return "", nil, nil, fmt.Errorf("action %q has empty runbook", spec.Name)
		}
		return spec.Runbook[0], append(append([]string{}, spec.Runbook[1:]...), args...), nil, nil
	}
	return buildSSHInvocation(spec, args, *opts.Host)
}

func buildSSHInvocation(spec actions.Spec, args []string, host config.Host) (string, []string, []byte, error) {
	if len(spec.Runbook) != 2 || spec.Runbook[0] != "bash" {
		return "", nil, nil, fmt.Errorf("action %q is not supported for ssh execution", spec.Name)
	}
	if strings.TrimSpace(host.Host) == "" {
		return "", nil, nil, fmt.Errorf("target host address is empty")
	}
	script, err := os.ReadFile(spec.Runbook[1])
	if err != nil {
		return "", nil, nil, err
	}
	return "ssh", buildSSHArgs(host, args), script, nil
}

func buildSSHArgs(host config.Host, args []string) []string {
	port := host.SSHPort
	if port <= 0 {
		port = 22
	}
	dest := strings.TrimSpace(host.Host)
	if user := strings.TrimSpace(host.SSHUser); user != "" {
		dest = user + "@" + dest
	}
	base := []string{"-p", strconv.Itoa(port), dest, "bash", "-s", "--"}
	return append(base, args...)
}
