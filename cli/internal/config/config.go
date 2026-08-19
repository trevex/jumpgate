// Package config loads and persists the jumpgate CLI configuration.
package config

import (
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
)

// Environment variables consulted when resolving the effective configuration.
const (
	envWardenAddr = "JUMPGATE_WARDEN_ADDR"
	envCAFile     = "JUMPGATE_CA"
	envToken      = "JUMPGATE_TOKEN"
)

// Config is the persisted CLI configuration.
type Config struct {
	WardenAddr string `json:"warden_addr"`
	CAFile     string `json:"ca_file"`
	Token      string `json:"token"`
}

// Path returns the location of the config file within the user config dir.
func Path() (string, error) {
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "jumpgate", "config.json"), nil
}

// Load reads the config file. A missing file yields a zero Config and no error;
// a malformed file yields an error.
func Load() (Config, error) {
	var c Config
	path, err := Path()
	if err != nil {
		return c, err
	}
	data, err := os.ReadFile(path) // #nosec G304 -- path is derived from os.UserConfigDir, not user input
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return c, nil
		}
		return c, err
	}
	if err := json.Unmarshal(data, &c); err != nil {
		return c, err
	}
	return c, nil
}

// Save writes the config to disk, creating the directory if needed. The
// directory is created 0700 and the file written 0600 since it holds a token.
func (c Config) Save() error {
	path, err := Path()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o600)
}

// Overlay returns a copy of c with values resolved by precedence: flag wins
// over env, which wins over the file value already held by c. Only non-empty
// values at each layer override the previous one.
func (c Config) Overlay(flags Config) Config {
	out := c
	out = out.mergeNonEmpty(fromEnv())
	out = out.mergeNonEmpty(flags)
	return out
}

// mergeNonEmpty returns a copy of c where each non-empty field of other wins.
func (c Config) mergeNonEmpty(other Config) Config {
	if other.WardenAddr != "" {
		c.WardenAddr = other.WardenAddr
	}
	if other.CAFile != "" {
		c.CAFile = other.CAFile
	}
	if other.Token != "" {
		c.Token = other.Token
	}
	return c
}

// fromEnv reads the config-related environment variables into a Config.
func fromEnv() Config {
	return Config{
		WardenAddr: os.Getenv(envWardenAddr),
		CAFile:     os.Getenv(envCAFile),
		Token:      os.Getenv(envToken),
	}
}
