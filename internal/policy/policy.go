package policy

import (
	"fmt"
	"os"
	"strings"

	"github.com/alan666gg/ops-agent/internal/actions"
	"gopkg.in/yaml.v3"
)

type Decision struct {
	Allowed          bool
	RequiresApproval bool
	Reason           string
}

type Config struct {
	Policies struct {
		AutoActions struct {
			Allowed         []string `yaml:"allowed"`
			RequireApproval []string `yaml:"require_approval"`
		} `yaml:"auto_actions"`
		ForbiddenCommands []string `yaml:"forbidden_commands"`
		Production        struct {
			RequireHumanApproval  bool `yaml:"require_human_approval"`
			MaxAutoActionsPerHour int  `yaml:"max_auto_actions_per_hour"`
		} `yaml:"production"`
	} `yaml:"policies"`
}

func Load(path string) (Config, error) {
	var cfg Config
	b, err := os.ReadFile(path)
	if err != nil {
		return cfg, err
	}
	if err := yaml.Unmarshal(b, &cfg); err != nil {
		return cfg, err
	}
	if err := cfg.Validate(); err != nil {
		return cfg, err
	}
	return cfg, nil
}

func (c Config) Validate() error {
	seen := map[string]string{}
	for _, name := range c.Policies.AutoActions.Allowed {
		if _, ok := actions.Lookup(name); !ok {
			return fmt.Errorf("policy references unsupported action %q", name)
		}
		if prev, exists := seen[name]; exists {
			return fmt.Errorf("action %q declared in both %s and allowed lists", name, prev)
		}
		seen[name] = "allowed"
	}
	for _, name := range c.Policies.AutoActions.RequireApproval {
		if _, ok := actions.Lookup(name); !ok {
			return fmt.Errorf("policy references unsupported action %q", name)
		}
		if prev, exists := seen[name]; exists {
			return fmt.Errorf("action %q declared in both %s and require_approval lists", name, prev)
		}
		seen[name] = "require_approval"
	}
	if c.Policies.Production.MaxAutoActionsPerHour < 0 {
		return fmt.Errorf("production.max_auto_actions_per_hour must be >= 0")
	}
	return nil
}

func (c Config) Evaluate(action, env string, recentAutoActions int) Decision {
	allowed, requiresApproval := c.ActionAllowed(action)
	if !allowed {
		return Decision{Allowed: false, Reason: "action denied by policy"}
	}
	if requiresApproval {
		return Decision{Allowed: true, RequiresApproval: true, Reason: "action requires approval by policy"}
	}
	if c.isProductionEnv(env) {
		if c.Policies.Production.RequireHumanApproval {
			return Decision{Allowed: true, RequiresApproval: true, Reason: "production policy requires human approval"}
		}
		if limit := c.Policies.Production.MaxAutoActionsPerHour; limit > 0 && recentAutoActions >= limit {
			return Decision{Allowed: true, RequiresApproval: true, Reason: fmt.Sprintf("production auto action limit reached (%d per hour)", limit)}
		}
	}
	return Decision{Allowed: true, Reason: "action allowed"}
}

func (c Config) isProductionEnv(env string) bool {
	normalized := strings.ToLower(strings.TrimSpace(env))
	return normalized == "prod" || normalized == "production"
}

func (c Config) ActionAllowed(action string) (bool, bool) {
	for _, a := range c.Policies.AutoActions.Allowed {
		if a == action {
			return true, false
		}
	}
	for _, a := range c.Policies.AutoActions.RequireApproval {
		if a == action {
			return true, true
		}
	}
	return false, false
}

func (c Config) ValidateAction(action string) error {
	ok, approval := c.ActionAllowed(action)
	if !ok {
		return fmt.Errorf("action %q is not allowed by policy", action)
	}
	if approval {
		return fmt.Errorf("action %q requires approval", action)
	}
	return nil
}
