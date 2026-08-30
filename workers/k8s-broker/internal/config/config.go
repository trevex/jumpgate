// Package config loads the k8s-broker's runtime configuration from env.
package config

import (
	"fmt"
	"os"
)

// Config is the k8s-broker's runtime configuration.
type Config struct {
	MeshCertFile string // BROKER_MESH_CERT (SPIFFE spiffe://jumpgate/broker/<id>)
	MeshKeyFile  string // BROKER_MESH_KEY
	MeshCAFile   string // BROKER_MESH_CA
	AgentListen  string // BROKER_AGENT_ADDR — mesh mTLS listener agents dial
	HealthAddr   string // BROKER_HEALTH_ADDR
}

// FromEnv loads config, failing closed on missing required values.
func FromEnv() (Config, error) {
	c := Config{
		MeshCertFile: os.Getenv("BROKER_MESH_CERT"),
		MeshKeyFile:  os.Getenv("BROKER_MESH_KEY"),
		MeshCAFile:   os.Getenv("BROKER_MESH_CA"),
		AgentListen:  envOr("BROKER_AGENT_ADDR", "0.0.0.0:9100"),
		HealthAddr:   envOr("BROKER_HEALTH_ADDR", "0.0.0.0:9101"),
	}
	if c.MeshCertFile == "" || c.MeshKeyFile == "" || c.MeshCAFile == "" {
		return Config{}, fmt.Errorf("missing required env (BROKER_MESH_CERT/KEY/CA)")
	}
	return c, nil
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}
