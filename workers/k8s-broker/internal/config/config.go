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

	WardenMeshAddr string // WARDEN_MESH_ADDR — host:port of warden's mesh listener
	WardenSpiffe   string // WARDEN_SPIFFE — pinned server identity
	BrokerID       string // BROKER_ID — must equal the broker's mesh SAN id
	DataplaneAddr  string // BROKER_DATAPLANE_ADDR — gateway-facing addr, advertised to warden

	RecordingBucket   string // RECORDING_S3_BUCKET — empty disables recording (k8s sessions then refused)
	RecordingEndpoint string // RECORDING_S3_ENDPOINT — custom S3 endpoint (self-hosted)
	RecordingRegion   string // RECORDING_S3_REGION
}

// FromEnv loads config, failing closed on missing required values.
func FromEnv() (Config, error) {
	c := Config{
		MeshCertFile: os.Getenv("BROKER_MESH_CERT"),
		MeshKeyFile:  os.Getenv("BROKER_MESH_KEY"),
		MeshCAFile:   os.Getenv("BROKER_MESH_CA"),
		AgentListen:  envOr("BROKER_AGENT_ADDR", "0.0.0.0:9100"),
		HealthAddr:   envOr("BROKER_HEALTH_ADDR", "0.0.0.0:9101"),

		WardenMeshAddr: os.Getenv("WARDEN_MESH_ADDR"),
		WardenSpiffe:   envOr("WARDEN_SPIFFE", "spiffe://jumpgate/warden/warden"),
		BrokerID:       os.Getenv("BROKER_ID"),
		DataplaneAddr:  envOr("BROKER_DATAPLANE_ADDR", "0.0.0.0:9102"),

		RecordingBucket:   os.Getenv("RECORDING_S3_BUCKET"),
		RecordingEndpoint: os.Getenv("RECORDING_S3_ENDPOINT"),
		RecordingRegion:   envOr("RECORDING_S3_REGION", "us-east-1"),
	}
	if c.MeshCertFile == "" || c.MeshKeyFile == "" || c.MeshCAFile == "" {
		return Config{}, fmt.Errorf("missing required env (BROKER_MESH_CERT/KEY/CA)")
	}
	if c.WardenMeshAddr == "" || c.BrokerID == "" {
		return Config{}, fmt.Errorf("missing required env (WARDEN_MESH_ADDR, BROKER_ID)")
	}
	return c, nil
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}
