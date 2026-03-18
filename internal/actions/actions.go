package actions

import (
	"fmt"
	"sort"
	"strings"
)

type Spec struct {
	Name        string
	Description string
	Runbook     []string
	MinArgs     int
	MaxArgs     int
}

var registry = map[string]Spec{
	"check_host_health": {
		Name:        "check_host_health",
		Description: "Collect host health basics from the current target",
		Runbook:     []string{"bash", "runbooks/check_host_health.sh"},
		MinArgs:     0,
		MaxArgs:     0,
	},
	"check_service_health": {
		Name:        "check_service_health",
		Description: "Check a service health endpoint",
		Runbook:     []string{"bash", "runbooks/check_service_health.sh"},
		MinArgs:     0,
		MaxArgs:     1,
	},
	"check_dependencies": {
		Name:        "check_dependencies",
		Description: "Check dependency endpoints in CSV form",
		Runbook:     []string{"bash", "runbooks/check_dependencies.sh"},
		MinArgs:     0,
		MaxArgs:     1,
	},
	"restart_container": {
		Name:        "restart_container",
		Description: "Restart a single container by name",
		Runbook:     []string{"bash", "runbooks/restart_container.sh"},
		MinArgs:     1,
		MaxArgs:     1,
	},
	"rollback_release": {
		Name:        "rollback_release",
		Description: "Rollback a container to a previous image",
		Runbook:     []string{"bash", "runbooks/rollback_release.sh"},
		MinArgs:     2,
		MaxArgs:     3,
	},
}

func Lookup(name string) (Spec, bool) {
	spec, ok := registry[strings.TrimSpace(name)]
	return spec, ok
}

func Names() []string {
	out := make([]string, 0, len(registry))
	for name := range registry {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

func ValidateArgs(name string, args []string) error {
	spec, ok := Lookup(name)
	if !ok {
		return fmt.Errorf("unknown action: %s", name)
	}
	if len(args) < spec.MinArgs {
		return fmt.Errorf("action %q requires at least %d args", name, spec.MinArgs)
	}
	if spec.MaxArgs >= 0 && len(args) > spec.MaxArgs {
		return fmt.Errorf("action %q allows at most %d args", name, spec.MaxArgs)
	}
	for _, arg := range args {
		if len(arg) > 300 || strings.Contains(arg, "\n") {
			return fmt.Errorf("invalid arg")
		}
	}
	return nil
}

func IsMutating(name string) bool {
	spec, ok := Lookup(name)
	if !ok {
		return false
	}
	return !strings.HasPrefix(spec.Name, "check_")
}
