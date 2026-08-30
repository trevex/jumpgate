// Package config loads the pg-proxy worker's runtime configuration from env.
package config

import (
	"fmt"
	"os"
	"strconv"
)

// Config is the pg-proxy worker's runtime configuration, all from env.
type Config struct {
	WorkerID       string // WORKER_ID — must equal the mesh leaf's SPIFFE id
	DataplaneAddr  string // WORKER_DATAPLANE_ADDR — listen+advertise addr for the gateway (later plan)
	HealthAddr     string // WORKER_HEALTH_ADDR — plaintext health port
	MeshCertFile   string // WORKER_MESH_CERT
	MeshKeyFile    string // WORKER_MESH_KEY
	MeshCAFile     string // WORKER_MESH_CA
	WardenMeshAddr string // WARDEN_MESH_ADDR — host:port of warden's mesh listener
	WardenSpiffe   string // WARDEN_SPIFFE — pinned server identity
	GatewaySpiffe  string // GATEWAY_SPIFFE — pinned client identity for the data-plane listener
	Capacity       int32  // WORKER_CAPACITY

	RecordingBucket   string // RECORDING_S3_BUCKET — empty disables recording upload
	RecordingEndpoint string // RECORDING_S3_ENDPOINT — custom S3 endpoint (self-hosted)
	RecordingRegion   string // RECORDING_S3_REGION
}

// FromEnv reads the config from the environment, failing closed on missing
// required values.
func FromEnv() (Config, error) {
	c := Config{
		WorkerID:       os.Getenv("WORKER_ID"),
		DataplaneAddr:  envOr("WORKER_DATAPLANE_ADDR", "0.0.0.0:9000"),
		HealthAddr:     envOr("WORKER_HEALTH_ADDR", "0.0.0.0:9001"),
		MeshCertFile:   os.Getenv("WORKER_MESH_CERT"),
		MeshKeyFile:    os.Getenv("WORKER_MESH_KEY"),
		MeshCAFile:     os.Getenv("WORKER_MESH_CA"),
		WardenMeshAddr: os.Getenv("WARDEN_MESH_ADDR"),
		WardenSpiffe:   envOr("WARDEN_SPIFFE", "spiffe://jumpgate/warden/warden"),
		GatewaySpiffe:  envOr("GATEWAY_SPIFFE", "spiffe://jumpgate/gateway/gateway"),
		Capacity:       capacityFromEnv(),

		RecordingBucket:   os.Getenv("RECORDING_S3_BUCKET"),
		RecordingEndpoint: os.Getenv("RECORDING_S3_ENDPOINT"),
		RecordingRegion:   envOr("RECORDING_S3_REGION", "us-east-1"),
	}
	if c.WorkerID == "" || c.MeshCertFile == "" || c.MeshKeyFile == "" || c.MeshCAFile == "" || c.WardenMeshAddr == "" {
		return Config{}, fmt.Errorf("missing required env (WORKER_ID, WORKER_MESH_CERT/KEY/CA, WARDEN_MESH_ADDR)")
	}
	return c, nil
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

// capacityFromEnv reads WORKER_CAPACITY, defaulting to 32 on unset/invalid.
func capacityFromEnv() int32 {
	if v := os.Getenv("WORKER_CAPACITY"); v != "" {
		if n, err := strconv.ParseInt(v, 10, 32); err == nil && n > 0 {
			return int32(n)
		}
	}
	return 32
}
