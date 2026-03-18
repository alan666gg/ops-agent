package checks

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/alan666gg/ops-agent/internal/config"
)

type fakeScriptRunner struct {
	output string
	err    error
}

func (r fakeScriptRunner) RunScript(_ context.Context, _ config.Host, _ time.Duration, _ string) (string, error) {
	return r.output, r.err
}

func TestRemoteHostResourceCheckerWarnsWhenThresholdExceeded(t *testing.T) {
	checker := RemoteHostResourceChecker{
		NameLabel: "host_resource_app_1",
		Host:      config.Host{Name: "app-1", Host: "10.0.0.5"},
		Checks: config.HostChecks{
			FilesystemPath: "/",
		},
		Runner: fakeScriptRunner{output: strings.Join([]string{
			"load1=3.4",
			"cpus=2",
			"memory_used_percent=86.2",
			"disk_used_percent=40",
			"inode_used_percent=12",
		}, "\n")},
	}

	result := checker.Run(context.Background())
	if result.Severity != SeverityWarn || result.Code != "HOST_RESOURCE_WARN" {
		t.Fatalf("unexpected result: %+v", result)
	}
	if !strings.Contains(result.Message, "load/cpu=1.70") || !strings.Contains(result.Message, "mem=86.2%") {
		t.Fatalf("unexpected message: %s", result.Message)
	}
}

func TestRemoteHostResourceCheckerFailsWhenSSHRunnerFails(t *testing.T) {
	checker := RemoteHostResourceChecker{
		NameLabel: "host_resource_app_1",
		Host:      config.Host{Name: "app-1", Host: "10.0.0.5"},
		Runner:    fakeScriptRunner{err: errors.New("boom")},
	}

	result := checker.Run(context.Background())
	if result.Severity != SeverityFail || result.Code != "HOST_RESOURCE_SSH_FAILED" {
		t.Fatalf("unexpected result: %+v", result)
	}
}

func TestRemoteProcessCheckerFailsOnMissingProcesses(t *testing.T) {
	checker := RemoteProcessChecker{
		NameLabel: "host_process_app_1",
		Host:      config.Host{Name: "app-1", Host: "10.0.0.5"},
		Processes: []string{"nginx", "redis-server"},
		Runner:    fakeScriptRunner{output: "missing=redis-server\n"},
	}

	result := checker.Run(context.Background())
	if result.Severity != SeverityFail || result.Code != "HOST_PROCESS_MISSING" {
		t.Fatalf("unexpected result: %+v", result)
	}
	if !strings.Contains(result.Message, "redis-server") {
		t.Fatalf("unexpected message: %s", result.Message)
	}
}

func TestParseMissingProcesses(t *testing.T) {
	got := parseMissingProcesses("missing=nginx, redis-server\n")
	if len(got) != 2 || got[0] != "nginx" || got[1] != "redis-server" {
		t.Fatalf("unexpected processes: %+v", got)
	}
}
