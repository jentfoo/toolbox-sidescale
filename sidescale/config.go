package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/jentfoo/toolbox-sidescale/sidescale/derp"
	"github.com/jentfoo/toolbox-sidescale/sidescale/noise"
)

const defaultName = "sidescale"

// SectoolConfig locates the sectool sidecar socket.
type SectoolConfig struct {
	Socket string `json:"socket,omitempty"`
}

// Config is the sidescale configuration surface.
type Config struct {
	Name    string               `json:"name,omitempty"`
	Sectool SectoolConfig        `json:"sectool,omitempty"`
	Control *noise.ControlConfig `json:"control,omitempty"` // always active
	Derp    *derp.DerpConfig     `json:"derp,omitempty"`    // opt-in; presence enables the DERP surface
}

// LoadConfig reads the config file at path, or returns an all-default config when path is empty.
func LoadConfig(path string) (Config, error) {
	var cfg Config
	if path != "" {
		data, err := os.ReadFile(path)
		if err != nil {
			return Config{}, fmt.Errorf("sidescale: read config %s: %w", path, err)
		}
		if err := json.Unmarshal(data, &cfg); err != nil {
			return Config{}, fmt.Errorf("sidescale: parse config %s: %w", path, err)
		}
	}
	cfg.applyDefaults()
	if err := cfg.validate(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

func (c *Config) applyDefaults() {
	if c.Name == "" {
		c.Name = defaultName
	}
	// control is always active (the /ts2021 claim is always emitted)
	if c.Control == nil {
		c.Control = &noise.ControlConfig{}
	}
	c.Control.ApplyDefaults()
	if c.Derp != nil {
		c.Derp.ApplyDefaults()
	}
}

func (c *Config) validate() error {
	if err := c.Control.Validate(); err != nil {
		return err
	}
	if c.Derp != nil {
		if err := c.Derp.Validate(); err != nil {
			return err
		}
	}
	return nil
}
