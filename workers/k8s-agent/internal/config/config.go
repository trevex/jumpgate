// Package config loads the k8s-agent's runtime configuration from env.
package config

import (
	"fmt"
	"os"
)

// Config is the k8s-agent's runtime configuration.
type Config struct {
	MeshCertFile string // AGENT_MESH_CERT — leaf cert (SPIFFE spiffe://jumpgate/agent/<asset_id>)
	MeshKeyFile  string // AGENT_MESH_KEY
	MeshCAFile   string // AGENT_MESH_CA
	BrokerAddr   string // BROKER_ADDR — host:port of the broker's agent listener

	// Local API server the agent proxies to (defaults derive from the in-cluster env).
	APIServerURL string // KUBE_APISERVER_URL — e.g. https://kubernetes.default.svc; falls back to KUBERNETES_SERVICE_HOST/PORT
	APIServerCA  string // KUBE_APISERVER_CA — path to the API server CA bundle
	SATokenFile  string // KUBE_SA_TOKEN_FILE — path to the agent's ServiceAccount token (re-read for kubelet rotation)

	HealthAddr string // AGENT_HEALTH_ADDR
}

// FromEnv loads config, failing closed on missing required values.
func FromEnv() (Config, error) {
	c := Config{
		MeshCertFile: os.Getenv("AGENT_MESH_CERT"),
		MeshKeyFile:  os.Getenv("AGENT_MESH_KEY"),
		MeshCAFile:   os.Getenv("AGENT_MESH_CA"),
		BrokerAddr:   os.Getenv("BROKER_ADDR"),
		APIServerURL: apiServerURL(),
		APIServerCA:  envOr("KUBE_APISERVER_CA", "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"),
		SATokenFile:  envOr("KUBE_SA_TOKEN_FILE", "/var/run/secrets/kubernetes.io/serviceaccount/token"),
		HealthAddr:   envOr("AGENT_HEALTH_ADDR", "0.0.0.0:9001"),
	}
	if c.MeshCertFile == "" || c.MeshKeyFile == "" || c.MeshCAFile == "" || c.BrokerAddr == "" || c.APIServerURL == "" {
		return Config{}, fmt.Errorf("missing required env (AGENT_MESH_CERT/KEY/CA, BROKER_ADDR, and a resolvable API server URL)")
	}
	return c, nil
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

// apiServerURL prefers KUBE_APISERVER_URL, else builds the in-cluster URL from
// the standard KUBERNETES_SERVICE_HOST/PORT env the kubelet injects.
func apiServerURL() string {
	if v := os.Getenv("KUBE_APISERVER_URL"); v != "" {
		return v
	}
	host, port := os.Getenv("KUBERNETES_SERVICE_HOST"), os.Getenv("KUBERNETES_SERVICE_PORT")
	if host != "" && port != "" {
		return fmt.Sprintf("https://%s:%s", host, port)
	}
	return ""
}
