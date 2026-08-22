package rpc_test

import (
	"testing"

	"connectrpc.com/connect"

	catalogv1 "github.com/trevex/jumpgate/warden/gen/jumpgate/catalog/v1"
)

func TestDeleteFolderBlocksWhenNonEmpty(t *testing.T) {
	env := newCatalogTestEnv(t)
	parent := env.createFolder(t, "prod")
	env.createChildFolder(t, "db", parent) // child folder makes it non-empty

	_, err := env.catalog.DeleteFolder(env.adminCtx, connect.NewRequest(&catalogv1.DeleteFolderRequest{FolderId: parent}))
	if connect.CodeOf(err) != connect.CodeFailedPrecondition {
		t.Fatalf("want FailedPrecondition for non-empty folder, got %v", err)
	}
}

func TestDeleteFolderSucceedsWhenEmpty(t *testing.T) {
	env := newCatalogTestEnv(t)
	f := env.createFolder(t, "empty")
	if _, err := env.catalog.DeleteFolder(env.adminCtx, connect.NewRequest(&catalogv1.DeleteFolderRequest{FolderId: f})); err != nil {
		t.Fatalf("DeleteFolder: %v", err)
	}
	_, err := env.catalog.ResolveFolder(env.adminCtx, connect.NewRequest(&catalogv1.ResolveFolderRequest{Ref: "empty"}))
	if connect.CodeOf(err) != connect.CodeNotFound {
		t.Fatalf("want NotFound after delete, got %v", err)
	}
}
