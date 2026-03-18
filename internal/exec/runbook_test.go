package exec

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/alan666gg/ops-agent/internal/actions"
	"github.com/alan666gg/ops-agent/internal/config"
)

func TestBuildInvocationLocal(t *testing.T) {
	spec := actions.Spec{
		Name:    "check_host_health",
		Runbook: []string{"bash", "runbooks/check_host_health.sh"},
	}
	name, args, stdin, err := buildInvocation(spec, []string{"one"}, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if name != "bash" {
		t.Fatalf("expected bash, got %s", name)
	}
	if len(args) != 2 || args[0] != "runbooks/check_host_health.sh" || args[1] != "one" {
		t.Fatalf("unexpected args: %#v", args)
	}
	if stdin != nil {
		t.Fatal("expected no stdin for local invocation")
	}
}

func TestBuildInvocationSSH(t *testing.T) {
	scriptPath := filepath.Join(t.TempDir(), "script.sh")
	if err := os.WriteFile(scriptPath, []byte("echo ok\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	spec := actions.Spec{
		Name:    "restart_container",
		Runbook: []string{"bash", scriptPath},
	}
	host := config.Host{Name: "app-1", Host: "10.0.0.5", SSHUser: "root", SSHPort: 2222}
	name, args, stdin, err := buildInvocation(spec, []string{"app"}, Options{Host: &host})
	if err != nil {
		t.Fatal(err)
	}
	if name != "ssh" {
		t.Fatalf("expected ssh, got %s", name)
	}
	want := []string{"-p", "2222", "root@10.0.0.5", "bash", "-s", "--", "app"}
	if len(args) != len(want) {
		t.Fatalf("unexpected arg length: %#v", args)
	}
	for i := range want {
		if args[i] != want[i] {
			t.Fatalf("arg %d: want %q, got %q", i, want[i], args[i])
		}
	}
	if string(stdin) != "echo ok\n" {
		t.Fatalf("unexpected stdin: %q", string(stdin))
	}
}
