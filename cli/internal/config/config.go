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

// Path returns the location of the config file within the user config dir.
func Path() (string, error) {
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "jumpgate", "config.json"), nil
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
