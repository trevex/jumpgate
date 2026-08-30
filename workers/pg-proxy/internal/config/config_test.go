package config

import (
	"os"
	"testing"
)

func TestCapacityFromEnv(t *testing.T) {
	base := map[string]string{
		"WORKER_ID": "pg-0", "WORKER_MESH_CERT": "c", "WORKER_MESH_KEY": "k",
		"WORKER_MESH_CA": "ca", "WARDEN_MESH_ADDR": "a",
	}
	set := func(extra map[string]string) {
		os.Clearenv()
		for k, v := range base {
			_ = os.Setenv(k, v)
		}
		for k, v := range extra {
			_ = os.Setenv(k, v)
		}
	}
	set(nil)
	if c, _ := FromEnv(); c.Capacity != 32 {
		t.Errorf("default Capacity = %d, want 32", c.Capacity)
	}
	set(map[string]string{"WORKER_CAPACITY": "7"})
	if c, _ := FromEnv(); c.Capacity != 7 {
		t.Errorf("Capacity = %d, want 7", c.Capacity)
	}
	set(map[string]string{"WORKER_CAPACITY": "notanint"})
	if c, _ := FromEnv(); c.Capacity != 32 {
		t.Errorf("bad WORKER_CAPACITY should fall back to 32, got %d", c.Capacity)
	}
}
