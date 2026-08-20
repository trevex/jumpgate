package cmd

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"connectrpc.com/connect"

	catalogv1 "github.com/trevex/jumpgate/warden/gen/jumpgate/catalog/v1"
	"github.com/trevex/jumpgate/warden/gen/jumpgate/catalog/v1/catalogv1connect"
)

type stubCatalog struct {
	catalogv1connect.UnimplementedCatalogServiceHandler
	gotCreate *catalogv1.CreateFolderRequest
}

func (s *stubCatalog) CreateFolder(_ context.Context, req *connect.Request[catalogv1.CreateFolderRequest]) (*connect.Response[catalogv1.CreateFolderResponse], error) {
	s.gotCreate = req.Msg
	return connect.NewResponse(&catalogv1.CreateFolderResponse{Folder: &catalogv1.Folder{
		Id:       "f1",
		Name:     req.Msg.GetName(),
		ParentId: req.Msg.GetParentId(),
	}}), nil
}

func (s *stubCatalog) ListFolders(_ context.Context, _ *connect.Request[catalogv1.ListFoldersRequest]) (*connect.Response[catalogv1.ListFoldersResponse], error) {
	return connect.NewResponse(&catalogv1.ListFoldersResponse{Folders: []*catalogv1.Folder{
		{Id: "f1", Name: "prod", ParentId: "root"},
	}}), nil
}

// newCatalogStub starts an httptest server serving the given catalog handler
// and returns its base URL.
func newCatalogStub(t *testing.T, h catalogv1connect.CatalogServiceHandler) string {
	t.Helper()
	mux := http.NewServeMux()
	mux.Handle(catalogv1connect.NewCatalogServiceHandler(h))
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv.URL
}

func TestFoldersCreate(t *testing.T) {
	s := &stubCatalog{}
	t.Setenv("JUMPGATE_WARDEN_ADDR", newCatalogStub(t, s))
	t.Setenv("JUMPGATE_TOKEN", "tok")
	t.Cleanup(func() { flagOutput = "table" })

	var out bytes.Buffer
	rootCmd.SetOut(&out)
	rootCmd.SetArgs([]string{"folders", "create", "prod", "-o", "json"})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("execute: %v", err)
	}

	if s.gotCreate.GetName() != "prod" {
		t.Fatalf("req=%+v", s.gotCreate)
	}
	if s.gotCreate.GetParentId() != "" {
		t.Fatalf("expected no parent, got %q", s.gotCreate.GetParentId())
	}
	if !strings.Contains(out.String(), "f1") {
		t.Fatalf("out=%s", out.String())
	}
}

func TestFoldersCreateWithParent(t *testing.T) {
	s := &stubCatalog{}
	t.Setenv("JUMPGATE_WARDEN_ADDR", newCatalogStub(t, s))
	t.Setenv("JUMPGATE_TOKEN", "tok")
	t.Cleanup(func() { flagOutput = "table" })

	var out bytes.Buffer
	rootCmd.SetOut(&out)
	rootCmd.SetArgs([]string{"folders", "create", "staging", "--parent", "root", "-o", "json"})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("execute: %v", err)
	}

	if s.gotCreate.GetName() != "staging" || s.gotCreate.GetParentId() != "root" {
		t.Fatalf("req=%+v", s.gotCreate)
	}
}

func TestFoldersList(t *testing.T) {
	t.Setenv("JUMPGATE_WARDEN_ADDR", newCatalogStub(t, &stubCatalog{}))
	t.Setenv("JUMPGATE_TOKEN", "tok")
	t.Cleanup(func() { flagOutput = "table" })

	var out bytes.Buffer
	rootCmd.SetOut(&out)
	rootCmd.SetArgs([]string{"folders", "list", "-o", "table"})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("execute: %v", err)
	}

	got := out.String()
	if !strings.Contains(got, "f1") || !strings.Contains(got, "prod") {
		t.Fatalf("out=%s", got)
	}
}

func TestFoldersListPathColumn(t *testing.T) {
	stub := &stubCatalogWithPath{}
	t.Setenv("JUMPGATE_WARDEN_ADDR", newCatalogStub(t, stub))
	t.Setenv("JUMPGATE_TOKEN", "tok")
	t.Cleanup(func() { flagOutput = "table" })

	var out bytes.Buffer
	rootCmd.SetOut(&out)
	rootCmd.SetArgs([]string{"folders", "list", "-o", "table"})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("execute: %v", err)
	}

	got := out.String()
	if !strings.Contains(got, "PATH") {
		t.Fatalf("folders table missing PATH column:\n%s", got)
	}
	if !strings.Contains(got, "prod.web") {
		t.Fatalf("folders table missing path value:\n%s", got)
	}
}

func TestFoldersCreatePathColumn(t *testing.T) {
	stub := &stubCatalogWithPath{}
	t.Setenv("JUMPGATE_WARDEN_ADDR", newCatalogStub(t, stub))
	t.Setenv("JUMPGATE_TOKEN", "tok")
	t.Cleanup(func() { flagOutput = "table" })

	var out bytes.Buffer
	rootCmd.SetOut(&out)
	rootCmd.SetArgs([]string{"folders", "create", "web", "-o", "table"})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("execute: %v", err)
	}

	got := out.String()
	if !strings.Contains(got, "PATH") {
		t.Fatalf("folders create table missing PATH column:\n%s", got)
	}
	if !strings.Contains(got, "prod.web") {
		t.Fatalf("folders create table missing path value:\n%s", got)
	}
}

// stubCatalogWithPath extends stubCatalog to return folders that carry a path.
type stubCatalogWithPath struct {
	catalogv1connect.UnimplementedCatalogServiceHandler
	gotCreate *catalogv1.CreateFolderRequest
}

func (s *stubCatalogWithPath) CreateFolder(_ context.Context, req *connect.Request[catalogv1.CreateFolderRequest]) (*connect.Response[catalogv1.CreateFolderResponse], error) {
	s.gotCreate = req.Msg
	return connect.NewResponse(&catalogv1.CreateFolderResponse{Folder: &catalogv1.Folder{
		Id:       "f2",
		Name:     req.Msg.GetName(),
		ParentId: req.Msg.GetParentId(),
		Path:     "prod.web",
	}}), nil
}

func (s *stubCatalogWithPath) ListFolders(_ context.Context, _ *connect.Request[catalogv1.ListFoldersRequest]) (*connect.Response[catalogv1.ListFoldersResponse], error) {
	return connect.NewResponse(&catalogv1.ListFoldersResponse{Folders: []*catalogv1.Folder{
		{Id: "f2", Name: "web", ParentId: "f1", Path: "prod.web"},
	}}), nil
}
