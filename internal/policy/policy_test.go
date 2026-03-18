package policy

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadRejectsUnsupportedAction(t *testing.T) {
	d := t.TempDir()
	path := filepath.Join(d, "policies.yaml")
	content := `policies:
  auto_actions:
    allowed:
      - check_host_health
    require_approval:
      - deploy_release
`
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	_, err := Load(path)
	if err == nil {
		t.Fatal("expected unsupported action error, got nil")
	}
}

func TestLoadAcceptsKnownActions(t *testing.T) {
	d := t.TempDir()
	path := filepath.Join(d, "policies.yaml")
	content := `policies:
  auto_actions:
    allowed:
      - check_host_health
    require_approval:
      - restart_container
`
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("expected valid policy, got %v", err)
	}
	ok, approval := cfg.ActionAllowed("restart_container")
	if !ok || !approval {
		t.Fatalf("unexpected action policy: ok=%v approval=%v", ok, approval)
	}
}

func TestEvaluateRequiresApprovalInProduction(t *testing.T) {
	cfg := Config{}
	cfg.Policies.AutoActions.Allowed = []string{"check_host_health"}
	cfg.Policies.Production.RequireHumanApproval = true

	decision := cfg.Evaluate("check_host_health", "prod", 0)
	if !decision.Allowed || !decision.RequiresApproval {
		t.Fatalf("expected production approval, got %+v", decision)
	}
}

func TestEvaluateRequiresApprovalWhenAutoLimitReached(t *testing.T) {
	cfg := Config{}
	cfg.Policies.AutoActions.Allowed = []string{"check_host_health"}
	cfg.Policies.Production.MaxAutoActionsPerHour = 2

	decision := cfg.Evaluate("check_host_health", "prod", 2)
	if !decision.Allowed || !decision.RequiresApproval {
		t.Fatalf("expected auto action limit to require approval, got %+v", decision)
	}
}
