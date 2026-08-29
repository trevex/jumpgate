package catalog_test

import (
	"testing"

	"connectrpc.com/connect"

	catalogv1 "github.com/trevex/jumpgate/warden/gen/jumpgate/catalog/v1"
)

// createPGAsset onboards a Postgres asset under folderID with an mtls login "readonly"
// and a password login "app" carrying an inline new_value secret; returns its id.
func (e *catalogTestEnv) createPGAsset(t *testing.T, folderID, name string, secret []byte) string {
	t.Helper()
	resp, err := e.catalog.CreateAsset(e.adminCtx, connect.NewRequest(&catalogv1.CreateAssetRequest{
		FolderId: folderID,
		Name:     name,
		Config: &catalogv1.CreateAssetRequest_Postgres{Postgres: &catalogv1.PostgresConfigInput{
			TargetAddress:   "10.0.0.9:5432",
			DefaultDatabase: "appdb",
			Logins: []*catalogv1.PostgresLoginInput{
				{Role: "readonly", Auth: &catalogv1.PostgresLoginInput_Mtls{Mtls: &catalogv1.MtlsAuth{}}},
				{Role: "app", Auth: &catalogv1.PostgresLoginInput_Password{Password: &catalogv1.SecretAuth{
					Source: &catalogv1.SecretAuth_NewValue{NewValue: secret}}}},
			},
		}},
	}))
	if err != nil {
		t.Fatalf("createPGAsset(%q): %v", name, err)
	}
	return resp.Msg.Asset.Id
}

func TestPostgresAssetOnboardRoundTrip(t *testing.T) {
	e := newCatalogTestEnv(t)
	fid := e.createFolder(t, "db")
	id := e.createPGAsset(t, fid, "primary", []byte("s3cr3t"))

	got, err := e.catalog.GetAsset(e.adminCtx, connect.NewRequest(&catalogv1.GetAssetRequest{AssetId: id}))
	if err != nil {
		t.Fatalf("GetAsset: %v", err)
	}
	a := got.Msg.Asset
	if a.Kind != "postgres" {
		t.Fatalf("kind = %q, want postgres", a.Kind)
	}
	pg := a.GetPostgres()
	if pg == nil {
		t.Fatal("asset has no postgres config")
	}
	if pg.TargetAddress != "10.0.0.9:5432" || pg.DefaultDatabase != "appdb" {
		t.Fatalf("config = %+v", pg)
	}
	if len(pg.Logins) != 2 {
		t.Fatalf("logins = %d, want 2", len(pg.Logins))
	}
	byRole := map[string]*catalogv1.PostgresLogin{}
	for _, l := range pg.Logins {
		byRole[l.Role] = l
	}
	if byRole["readonly"].Kind != "mtls" || byRole["readonly"].SecretId != "" {
		t.Fatalf("readonly login = %+v, want mtls with no secret", byRole["readonly"])
	}
	if byRole["app"].Kind != "password" || byRole["app"].SecretId == "" {
		t.Fatalf("app login = %+v, want password with a secret", byRole["app"])
	}
}

func TestPostgresAssetPasswordRequiresSecret(t *testing.T) {
	e := newCatalogTestEnv(t)
	fid := e.createFolder(t, "db")
	_, err := e.catalog.CreateAsset(e.adminCtx, connect.NewRequest(&catalogv1.CreateAssetRequest{
		FolderId: fid,
		Name:     "primary",
		Config: &catalogv1.CreateAssetRequest_Postgres{Postgres: &catalogv1.PostgresConfigInput{
			TargetAddress: "10.0.0.9:5432",
			Logins: []*catalogv1.PostgresLoginInput{
				{Role: "app", Auth: &catalogv1.PostgresLoginInput_Password{Password: &catalogv1.SecretAuth{
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
