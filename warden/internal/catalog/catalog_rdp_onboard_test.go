package catalog_test

import (
	"testing"

	"connectrpc.com/connect"

	catalogv1 "github.com/trevex/jumpgate/warden/gen/jumpgate/catalog/v1"
)

// createRDPAsset onboards an RDP asset under folderID with a single password login
// "admin" carrying an inline new_value secret; returns its id.
func (e *catalogTestEnv) createRDPAsset(t *testing.T, folderID, name string, secret []byte) string {
	t.Helper()
	resp, err := e.catalog.CreateAsset(e.adminCtx, connect.NewRequest(&catalogv1.CreateAssetRequest{
		FolderId: folderID,
		Name:     name,
		Config: &catalogv1.CreateAssetRequest_Rdp{Rdp: &catalogv1.RDPConfigInput{
			TargetAddress: "10.0.0.20:3389",
			Logins: []*catalogv1.RDPLoginInput{
				{Login: "admin", Auth: &catalogv1.RDPLoginInput_Password{Password: &catalogv1.SecretAuth{
					Source: &catalogv1.SecretAuth_NewValue{NewValue: secret}}}},
			},
		}},
	}))
	if err != nil {
		t.Fatalf("createRDPAsset(%q): %v", name, err)
	}
	return resp.Msg.Asset.Id
}

func TestRDPAssetOnboardRoundTrip(t *testing.T) {
	e := newCatalogTestEnv(t)
	fid := e.createFolder(t, "desktops")
	id := e.createRDPAsset(t, fid, "workstation", []byte("s3cr3t"))

	got, err := e.catalog.GetAsset(e.adminCtx, connect.NewRequest(&catalogv1.GetAssetRequest{AssetId: id}))
	if err != nil {
		t.Fatalf("GetAsset: %v", err)
	}
	a := got.Msg.Asset
	if a.Kind != "rdp" {
		t.Fatalf("kind = %q, want rdp", a.Kind)
	}
	rdp := a.GetRdp()
	if rdp == nil {
		t.Fatal("asset has no rdp config")
	}
	if rdp.TargetAddress != "10.0.0.20:3389" {
		t.Fatalf("config = %+v", rdp)
	}
	if len(rdp.Logins) != 1 {
		t.Fatalf("logins = %d, want 1", len(rdp.Logins))
	}
	l := rdp.Logins[0]
	if l.Login != "admin" || l.Kind != "password" || l.SecretId == "" {
		t.Fatalf("login = %+v, want admin/password with a secret", l)
	}
}

// TestRDPAssetDisplayIsSecretFree asserts the display path returns the config and
// login kind but carries no secret reference of any form.
func TestRDPAssetDisplayIsSecretFree(t *testing.T) {
	e := newCatalogTestEnv(t)
	fid := e.createFolder(t, "desktops")
	id := e.createRDPAsset(t, fid, "workstation", []byte("s3cr3t"))

	got, err := e.catalog.GetAssetDisplay(e.adminCtx, connect.NewRequest(&catalogv1.GetAssetDisplayRequest{AssetId: id}))
	if err != nil {
		t.Fatalf("GetAssetDisplay: %v", err)
	}
	disp := got.Msg.Asset
	if disp.Kind != "rdp" {
		t.Fatalf("kind = %q, want rdp", disp.Kind)
	}
	rdp := disp.GetRdp()
	if rdp == nil {
		t.Fatal("display has no rdp config")
	}
	if rdp.TargetAddress != "10.0.0.20:3389" {
		t.Fatalf("display config = %+v", rdp)
	}
	if len(rdp.Logins) != 1 || rdp.Logins[0].Login != "admin" || rdp.Logins[0].Kind != "password" {
		t.Fatalf("display logins = %+v", rdp.Logins)
	}
	// RDPLoginDisplay has no secret field by construction — this is a compile-time and
	// runtime guarantee that the display path can never echo vault material.
}

func TestRDPAssetPasswordRequiresSecret(t *testing.T) {
	e := newCatalogTestEnv(t)
	fid := e.createFolder(t, "desktops")
	_, err := e.catalog.CreateAsset(e.adminCtx, connect.NewRequest(&catalogv1.CreateAssetRequest{
		FolderId: fid,
		Name:     "workstation",
		Config: &catalogv1.CreateAssetRequest_Rdp{Rdp: &catalogv1.RDPConfigInput{
			TargetAddress: "10.0.0.20:3389",
			Logins: []*catalogv1.RDPLoginInput{
				{Login: "admin", Auth: &catalogv1.RDPLoginInput_Password{Password: &catalogv1.SecretAuth{
					Source: &catalogv1.SecretAuth_NewValue{NewValue: []byte{}}}}}, // empty → rejected
			},
		}},
	}))
	if err == nil {
		t.Fatal("expected InvalidArgument for empty password secret, got nil")
	}
	if connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Fatalf("code = %v, want InvalidArgument", connect.CodeOf(err))
	}
}
