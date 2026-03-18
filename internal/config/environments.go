package config

import (
	"os"

	"gopkg.in/yaml.v3"
)

type EnvironmentFile struct {
	Environments map[string]Environment `yaml:"environments"`
}

type Environment struct {
	Hosts        []Host    `yaml:"hosts"`
	Services     []Service `yaml:"services"`
	Dependencies []string  `yaml:"dependencies"`
}

type Host struct {
	Name    string `yaml:"name"`
	Host    string `yaml:"host"`
	SSHUser string `yaml:"ssh_user"`
	SSHPort int    `yaml:"ssh_port"`
}

type Service struct {
	Name           string `yaml:"name"`
	Type           string `yaml:"type"`
	ContainerName  string `yaml:"container_name"`
	HealthcheckURL string `yaml:"healthcheck_url"`
}

func LoadEnvironments(path string) (EnvironmentFile, error) {
	var out EnvironmentFile
	b, err := os.ReadFile(path)
	if err != nil {
		return out, err
	}
	if err := yaml.Unmarshal(b, &out); err != nil {
		return out, err
	}
	if out.Environments == nil {
		out.Environments = map[string]Environment{}
	}
	return out, nil
}
