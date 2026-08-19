// Package config loads and persists the jumpgate CLI configuration.
package config

import (
	"encoding/json"
	"errors"
	"fmt"
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

// Context is one named identity + endpoint.
type Context struct {
	WardenAddr string `json:"warden_addr"`
	CAFile     string `json:"ca_file,omitempty"`
	Token      string `json:"token"`
	IsAdmin    bool   `json:"is_admin,omitempty"`
}

// File is the persisted CLI configuration: named contexts + the current one.
type File struct {
	CurrentContext string             `json:"current_context"`
	Contexts       map[string]Context `json:"contexts"`
}

// Overrides are per-invocation flag values (empty = unset).
type Overrides struct{ WardenAddr, CAFile, Token string }

// LoadFile reads and, if needed, migrates the config file to the contexts shape.
// A missing file yields an empty File. An old flat config ({"token",...} with no
// "contexts") is migrated into a "default" context.
func LoadFile() (File, error) {
	var f File
	path, err := Path()
	if err != nil {
		return f, err
	}
	data, err := os.ReadFile(path) // #nosec G304 -- path derived from os.UserConfigDir
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return File{Contexts: map[string]Context{}}, nil
		}
		return f, err
	}
	if err := json.Unmarshal(data, &f); err != nil {
		return File{}, err
	}
	if f.Contexts == nil {
		f.Contexts = map[string]Context{}
	}
	if len(f.Contexts) == 0 {
		var flat struct {
			WardenAddr string `json:"warden_addr"`
			CAFile     string `json:"ca_file"`
			Token      string `json:"token"`
		}
		_ = json.Unmarshal(data, &flat)
		if flat.Token != "" || flat.WardenAddr != "" {
			f.Contexts["default"] = Context{WardenAddr: flat.WardenAddr, CAFile: flat.CAFile, Token: flat.Token}
			f.CurrentContext = "default"
		}
	}
	return f, nil
}

// Save writes the contexts file (dir 0700, file 0600 — it holds tokens).
func (f File) Save() error {
	path, err := Path()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(File{CurrentContext: f.CurrentContext, Contexts: f.Contexts}, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o600)
}

// Resolve returns the effective Context: pick contextName (or CurrentContext),
// then overlay env, then flag overrides (flag > env > context).
func Resolve(contextName string, o Overrides) (Context, error) {
	f, err := LoadFile()
	if err != nil {
		return Context{}, err
	}
	name := contextName
	if name == "" {
		name = f.CurrentContext
	}
	ctx := f.Contexts[name]
	if v := os.Getenv(envWardenAddr); v != "" {
		ctx.WardenAddr = v
	}
	if v := os.Getenv(envCAFile); v != "" {
		ctx.CAFile = v
	}
	if v := os.Getenv(envToken); v != "" {
		ctx.Token = v
	}
	if o.WardenAddr != "" {
		ctx.WardenAddr = o.WardenAddr
	}
	if o.CAFile != "" {
		ctx.CAFile = o.CAFile
	}
	if o.Token != "" {
		ctx.Token = o.Token
	}
	return ctx, nil
}

// UpsertContext writes/updates a context; makeCurrent (or an empty current) selects it.
func UpsertContext(name string, ctx Context, makeCurrent bool) error {
	f, err := LoadFile()
	if err != nil {
		return err
	}
	if f.Contexts == nil {
		f.Contexts = map[string]Context{}
	}
	f.Contexts[name] = ctx
	if makeCurrent || f.CurrentContext == "" {
		f.CurrentContext = name
	}
	return f.Save()
}

// UseContext sets the current context (must already exist).
func UseContext(name string) error {
	f, err := LoadFile()
	if err != nil {
		return err
	}
	if _, ok := f.Contexts[name]; !ok {
		return fmt.Errorf("no context named %q", name)
	}
	f.CurrentContext = name
	return f.Save()
}
