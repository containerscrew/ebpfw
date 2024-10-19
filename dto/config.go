package dto

import (
	"io"
	"os"

	"github.com/pelletier/go-toml"
)

type Config struct {
	Global struct {
		InterfaceName string `toml:"interface_name"`
	}
	Log struct {
		Level string `toml:"level"`
		Type  string `toml:"type"`
	}
	Firewall FirewallConfig `toml:"firewall"`
}

type FirewallConfig struct {
	DefaultDeny		 bool        `toml:"default_deny"`
    AllowedPorts     []int       `toml:"allowed_ports"`
}

func ReadConfigFile() (Config, error) {
	file, err := os.Open("config.toml")
	if err != nil {
		return Config{}, err
	}
	defer file.Close()

	var config Config

	b, err := io.ReadAll(file)
	if err != nil {
		return Config{}, err
	}

	err = toml.Unmarshal(b, &config)
	if err != nil {
		return Config{}, err
	}

	return config, nil
}