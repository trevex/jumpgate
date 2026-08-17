// Package config loads control-plane configuration from the environment.
package config

import (
	"time"

	"github.com/caarlos0/env/v11"
)

// Config is the control-plane runtime configuration.
type Config struct {
	DatabaseURL     string        `env:"DATABASE_URL,required"`
	ListenAddr      string        `env:"LISTEN_ADDR" envDefault:":8080"`
	LogLevel        string        `env:"LOG_LEVEL" envDefault:"info"`
	ShutdownTimeout time.Duration `env:"SHUTDOWN_TIMEOUT" envDefault:"15s"`

	BootstrapAdminEmail    string `env:"BOOTSTRAP_ADMIN_EMAIL"`
	BootstrapAdminPassword string `env:"BOOTSTRAP_ADMIN_PASSWORD"`
}

// Load reads configuration from environment variables.
func Load() (Config, error) {
	var c Config
	if err := env.Parse(&c); err != nil {
		return Config{}, err
	}
	return c, nil
}
