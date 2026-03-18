package policy

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Policies struct {
		AutoActions struct {
			Allowed         []string `yaml:"allowed"`
			RequireApproval []string `yaml:"require_approval"`
		} `yaml:"auto_actions"`
		ForbiddenCommands []string `yaml:"forbidden_commands"`
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
	return cfg, nil
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
