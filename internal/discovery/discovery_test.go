package discovery

import (
	"strings"
	"testing"

	"github.com/alan666gg/ops-agent/internal/config"
)

func TestParseDiscoveryReport(t *testing.T) {
	output := strings.Join([]string{
		"@@SECTION:docker@@",
		`{"Names":"api","Image":"my-api:1.2.3","Status":"Up 2 hours","Ports":"0.0.0.0:8080->80/tcp, :::8080->80/tcp"}`,
		`{"Names":"worker","Image":"my-worker:1.2.3","Status":"Up 2 hours","Ports":""}`,
		"@@SECTION:systemd@@",
		"nginx.service loaded active running A high performance web server",
		"redis.service loaded active running Advanced key-value store",
		"@@SECTION:listeners@@",
		"LISTEN 0 4096 0.0.0.0:22 0.0.0.0:* users:((\"sshd\",pid=100,fd=3))",
		"LISTEN 0 4096 0.0.0.0:8080 0.0.0.0:* users:((\"docker-proxy\",pid=200,fd=4))",
	}, "\n")

	report, err := Parse(output, config.Host{Name: "app-1", Host: "10.0.0.5"})
	if err != nil {
		t.Fatal(err)
	}
	if report.HostName != "app-1" || report.HostAddress != "10.0.0.5" {
		t.Fatalf("unexpected host metadata: %+v", report)
	}
	if len(report.Containers) != 2 || report.Containers[0].Name != "api" {
		t.Fatalf("unexpected containers: %+v", report.Containers)
	}
	if len(report.SystemdServices) != 2 || report.SystemdServices[0].Name != "nginx.service" {
		t.Fatalf("unexpected systemd services: %+v", report.SystemdServices)
	}
	if len(report.Listeners) != 2 || report.Listeners[1].Port != 8080 {
		t.Fatalf("unexpected listeners: %+v", report.Listeners)
	}
	if len(report.SuggestedService) != 2 {
		t.Fatalf("unexpected suggested services: %+v", report.SuggestedService)
	}
	if got := report.SuggestedService[0].CandidateHealthURLs; len(got) != 1 || got[0] != "http://10.0.0.5:8080/" {
		t.Fatalf("unexpected candidate health urls: %+v", report.SuggestedService[0])
	}
}

func TestExtractPublishedPorts(t *testing.T) {
	got := extractPublishedPorts("0.0.0.0:8080->80/tcp, :::9090->90/tcp")
	if len(got) != 2 || got[0] != 8080 || got[1] != 9090 {
		t.Fatalf("unexpected ports: %+v", got)
	}
}

func TestBuildSSHArgs(t *testing.T) {
	args := buildSSHArgs(config.Host{Name: "app-1", Host: "10.0.0.5", SSHUser: "root", SSHPort: 2222})
	want := []string{"-p", "2222", "root@10.0.0.5", "sh", "-s"}
	if len(args) != len(want) {
		t.Fatalf("unexpected args len: %+v", args)
	}
	for i := range want {
		if args[i] != want[i] {
			t.Fatalf("arg %d want %q got %q", i, want[i], args[i])
		}
	}
}
