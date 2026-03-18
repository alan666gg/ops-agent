package chatops

import (
	"fmt"
	"os"
	"strings"

	"github.com/alan666gg/ops-agent/internal/actions"
	"gopkg.in/yaml.v3"
)

const (
	roleViewer   = "viewer"
	roleOperator = "operator"
	roleApprover = "approver"
	roleAdmin    = "admin"
)

type SecurityConfig struct {
	Users         []UserRule `yaml:"users"`
	DenyPatterns  []string   `yaml:"deny_patterns"`
	MaxInputChars int        `yaml:"max_input_chars"`
}

type UserRule struct {
	Actor          string   `yaml:"actor"`
	Role           string   `yaml:"role"`
	AllowedActions []string `yaml:"allowed_actions"`
}

type Authorizer struct {
	cfg   SecurityConfig
	users map[string]UserRule
}

func DefaultSecurityConfig() SecurityConfig {
	return SecurityConfig{
		DenyPatterns: []string{
			"ignore previous instructions",
			"ignore all previous instructions",
			"system prompt",
			"developer message",
			"reveal hidden instructions",
		},
		MaxInputChars: 1200,
	}
}

func LoadSecurityConfig(path string) (SecurityConfig, error) {
	cfg := DefaultSecurityConfig()
	if strings.TrimSpace(path) == "" {
		return cfg, nil
	}
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

func (c *SecurityConfig) applyDefaults() {
	defaults := DefaultSecurityConfig()
	if c.MaxInputChars <= 0 {
		c.MaxInputChars = defaults.MaxInputChars
	}
	if len(c.DenyPatterns) == 0 {
		c.DenyPatterns = append([]string{}, defaults.DenyPatterns...)
	}
}

func (c SecurityConfig) Validate() error {
	c.applyDefaults()
	seen := map[string]struct{}{}
	for _, user := range c.Users {
		actor := strings.TrimSpace(user.Actor)
		if actor == "" {
			return fmt.Errorf("chatops user actor is required")
		}
		if _, ok := seen[actor]; ok {
			return fmt.Errorf("duplicate chatops actor %q", actor)
		}
		seen[actor] = struct{}{}
		role := strings.ToLower(strings.TrimSpace(user.Role))
		if roleRank(role) == 0 {
			return fmt.Errorf("unsupported chatops role %q", user.Role)
		}
		for _, action := range user.AllowedActions {
			if _, ok := actions.Lookup(action); !ok {
				return fmt.Errorf("chatops actor %q references unsupported action %q", actor, action)
			}
		}
	}
	if c.MaxInputChars <= 0 {
		return fmt.Errorf("chatops max_input_chars must be > 0")
	}
	return nil
}

func NewAuthorizer(cfg SecurityConfig) Authorizer {
	cfg.applyDefaults()
	users := make(map[string]UserRule, len(cfg.Users))
	for _, user := range cfg.Users {
		user.Actor = strings.TrimSpace(user.Actor)
		user.Role = strings.ToLower(strings.TrimSpace(user.Role))
		users[user.Actor] = user
	}
	return Authorizer{cfg: cfg, users: users}
}

func (a Authorizer) UserCount() int {
	return len(a.users)
}

func (a Authorizer) AuthorizeInput(actor, input string) error {
	if _, err := a.user(actor); err != nil {
		return err
	}
	if len([]rune(strings.TrimSpace(input))) > a.cfg.MaxInputChars {
		return fmt.Errorf("input exceeds the %d character limit", a.cfg.MaxInputChars)
	}
	normalized := strings.ToLower(strings.TrimSpace(input))
	for _, pattern := range a.cfg.DenyPatterns {
		pattern = strings.ToLower(strings.TrimSpace(pattern))
		if pattern == "" {
			continue
		}
		if strings.Contains(normalized, pattern) {
			return fmt.Errorf("input blocked by chatops security policy")
		}
	}
	return nil
}

func (a Authorizer) AuthorizeCommand(actor string, cmd Command) error {
	switch cmd.Name {
	case "start", "help", "reset", "health", "incidents", "pending", "requests", "show":
		_, err := a.requireRole(actor, roleViewer)
		return err
	case "request":
		if _, err := a.requireRole(actor, roleOperator); err != nil {
			return err
		}
		return a.allowAction(actor, cmd.Action)
	case "approve", "reject":
		_, err := a.requireRole(actor, roleApprover)
		return err
	default:
		_, err := a.user(actor)
		return err
	}
}

func (a Authorizer) AuthorizeCallback(actor, data string) error {
	switch {
	case strings.HasPrefix(data, "approve:"), strings.HasPrefix(data, "reject:"):
		_, err := a.requireRole(actor, roleApprover)
		return err
	case strings.HasPrefix(data, "show:"), data == "llm_confirm", data == "llm_cancel":
		_, err := a.user(actor)
		return err
	default:
		return fmt.Errorf("unsupported callback")
	}
}

func (a Authorizer) AuthorizeTool(actor, toolName string, args map[string]any) error {
	switch toolName {
	case "get_health", "get_incident_summary", "list_pending", "list_actions", "get_action":
		_, err := a.requireRole(actor, roleViewer)
		return err
	case "request_action":
		if _, err := a.requireRole(actor, roleOperator); err != nil {
			return err
		}
		return a.allowAction(actor, stringFromAny(args["action"]))
	case "approve_action", "reject_action":
		_, err := a.requireRole(actor, roleApprover)
		return err
	default:
		return fmt.Errorf("unsupported tool %q", toolName)
	}
}

func (a Authorizer) user(actor string) (UserRule, error) {
	actor = strings.TrimSpace(actor)
	if actor == "" {
		return UserRule{}, fmt.Errorf("missing actor")
	}
	if len(a.users) == 0 {
		return UserRule{Actor: actor, Role: roleAdmin}, nil
	}
	user, ok := a.users[actor]
	if !ok {
		return UserRule{}, fmt.Errorf("telegram actor %q is not allowed", actor)
	}
	return user, nil
}

func (a Authorizer) requireRole(actor, minRole string) (UserRule, error) {
	user, err := a.user(actor)
	if err != nil {
		return UserRule{}, err
	}
	if roleRank(user.Role) < roleRank(minRole) {
		return UserRule{}, fmt.Errorf("telegram actor %q with role %q is not allowed to perform this operation", actor, user.Role)
	}
	return user, nil
}

func (a Authorizer) allowAction(actor, action string) error {
	user, err := a.user(actor)
	if err != nil {
		return err
	}
	if len(user.AllowedActions) == 0 {
		return nil
	}
	for _, allowed := range user.AllowedActions {
		if allowed == action {
			return nil
		}
	}
	return fmt.Errorf("telegram actor %q is not allowed to request action %q", actor, action)
}

func roleRank(role string) int {
	switch strings.ToLower(strings.TrimSpace(role)) {
	case roleViewer:
		return 1
	case roleOperator:
		return 2
	case roleApprover:
		return 3
	case roleAdmin:
		return 4
	default:
		return 0
	}
}
