package catalog_test

import (
	"testing"

	"connectrpc.com/connect"

	catalogv1 "github.com/trevex/jumpgate/warden/gen/jumpgate/catalog/v1"
)

// createK8sAsset onboards a k8s asset under folderID with no config (a k8s asset
// stores no endpoint, credential, or logins); returns its id.
func (e *catalogTestEnv) createK8sAsset(t *testing.T, folderID, name string) string {
	t.Helper()
	resp, err := e.catalog.CreateAsset(e.adminCtx, connect.NewRequest(&catalogv1.CreateAssetRequest{
		FolderId: folderID,
		Name:     name,
		Config:   &catalogv1.CreateAssetRequest_Kubernetes{Kubernetes: &catalogv1.KubernetesConfigInput{}},
	}))
	if err != nil {
		t.Fatalf("createK8sAsset(%q): %v", name, err)
	}
	return resp.Msg.Asset.Id
}

func TestCreateKubernetesAsset(t *testing.T) {
	e := newCatalogTestEnv(t)
	fid := e.createFolder(t, "clusters")
	id := e.createK8sAsset(t, fid, "prod-cluster")

	got, err := e.catalog.GetAsset(e.adminCtx, connect.NewRequest(&catalogv1.GetAssetRequest{AssetId: id}))
	if err != nil {
		t.Fatalf("GetAsset: %v", err)
	}
	a := got.Msg.Asset
	if a.Kind != "k8s" {
		t.Fatalf("kind = %q, want k8s", a.Kind)
	}
	if a.Id == "" {
		t.Fatal("empty asset id")
	}
	// A k8s asset carries no config oneof arm.
	if a.GetSsh() != nil || a.GetPostgres() != nil {
		t.Fatalf("k8s asset should carry no config, got %+v", a.Config)
	}
}
