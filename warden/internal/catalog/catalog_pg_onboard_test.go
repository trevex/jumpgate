package catalog_test

import (
	"context"
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

// updatePGConfig drives UpdateAssetConfig for a postgres asset with the given target
// address and default database (readonly mtls + app password with a rotated secret,
// matching createPGAsset's login set), exercising the pg create/update probe hooks.
func (e *catalogTestEnv) updatePGConfig(t *testing.T, assetID, targetAddress, database string, secret []byte) {
	t.Helper()
	_, err := e.catalog.UpdateAssetConfig(e.adminCtx, connect.NewRequest(&catalogv1.UpdateAssetConfigRequest{
		AssetId: assetID,
		Config: &catalogv1.UpdateAssetConfigRequest_Postgres{Postgres: &catalogv1.PostgresConfigInput{
			TargetAddress:   targetAddress,
			DefaultDatabase: database,
			Logins: []*catalogv1.PostgresLoginInput{
				{Role: "readonly", Auth: &catalogv1.PostgresLoginInput_Mtls{Mtls: &catalogv1.MtlsAuth{}}},
				{Role: "app", Auth: &catalogv1.PostgresLoginInput_Password{Password: &catalogv1.SecretAuth{
					Source: &catalogv1.SecretAuth_NewValue{NewValue: secret}}}},
			},
		}},
	}))
	if err != nil {
		t.Fatalf("UpdateAssetConfig(postgres): %v", err)
	}
}

// seedPGMigrationAnchor inserts an approved migration-source tls_ca anchor at the
// asset's current revision, standing in for trust the pg migration established.
func (e *catalogTestEnv) seedPGMigrationAnchor(t *testing.T, assetID string) {
	t.Helper()
	if _, err := e.pool.Exec(context.Background(), `
		INSERT INTO target_trust_anchors (asset_id, endpoint_revision, kind, algorithm, sha256_fingerprint, public_material, source, required_dns_names)
		SELECT id, endpoint_revision, 'tls_ca', 'ecdsa', 'SHA256:pg-seeded', 'ca-pem', 'migration', ARRAY['10.0.0.9']
		FROM assets WHERE id = $1`, assetID); err != nil {
		t.Fatalf("seed pg migration anchor: %v", err)
	}
}

// TestCreatePostgresAssetQueuesOnboardingProbe covers correctness req 5 for postgres:
// a created pg asset persists at revision 1 and gets exactly one queued onboarding
// probe at that same revision (protocol postgres), in one logical operation.
func TestCreatePostgresAssetQueuesOnboardingProbe(t *testing.T) {
	env := newCatalogTestEnv(t)
	folderID := env.createFolder(t, "prod")
	assetID := env.createPGAsset(t, folderID, "pgbox", []byte("s3cr3t")) // 10.0.0.9:5432, rev 1

	if rev := env.endpointRevision(t, assetID); rev != 1 {
		t.Fatalf("endpoint revision = %d; want 1", rev)
	}
	var rev int64
	var protocol, reason, state string
	if err := env.pool.QueryRow(context.Background(),
		`SELECT endpoint_revision, protocol, reason, state FROM target_probe_jobs WHERE asset_id = $1`, assetID).Scan(&rev, &protocol, &reason, &state); err != nil {
		t.Fatalf("read probe job: %v", err)
	}
	if rev != 1 || protocol != "postgres" || reason != "onboarding" || state != "queued" {
		t.Fatalf("probe job rev=%d protocol=%q reason=%q state=%q; want 1/postgres/onboarding/queued", rev, protocol, reason, state)
	}
	if n := env.count(t, `SELECT count(*) FROM target_probe_jobs WHERE asset_id = $1`, assetID); n != 1 {
		t.Fatalf("probe jobs = %d; want exactly 1", n)
	}
}

// TestUpdatePostgresAssetAddressChangeIncrementsRevisionAndQueuesProbe covers req 3
// for postgres: a target-address change increments the endpoint revision (invalidating
// old anchors) and queues a fresh probe at the new revision.
func TestUpdatePostgresAssetAddressChangeIncrementsRevisionAndQueuesProbe(t *testing.T) {
	env := newCatalogTestEnv(t)
	folderID := env.createFolder(t, "prod")
	assetID := env.createPGAsset(t, folderID, "pgbox", []byte("s3cr3t")) // 10.0.0.9:5432, rev 1, onboarding probe
	env.seedPGMigrationAnchor(t, assetID)
	if n := env.currentAnchorCount(t, assetID); n != 1 {
		t.Fatalf("seeded current anchors = %d; want 1", n)
	}

	env.updatePGConfig(t, assetID, "10.0.0.11:5432", "appdb", []byte("s3cr3t"))

	if rev := env.endpointRevision(t, assetID); rev != 2 {
		t.Fatalf("endpoint revision = %d; want 2 after target-address change", rev)
	}
	if n := env.currentAnchorCount(t, assetID); n != 0 {
		t.Fatalf("current anchors after endpoint change = %d; want 0 (old anchors invalidated)", n)
	}
	var rev int64
	if err := env.pool.QueryRow(context.Background(),
		`SELECT endpoint_revision FROM target_probe_jobs WHERE asset_id = $1 AND reason = 'endpoint_changed'`, assetID).Scan(&rev); err != nil {
		t.Fatalf("read endpoint_changed probe: %v", err)
	}
	if rev != 2 {
		t.Fatalf("endpoint_changed probe revision = %d; want 2", rev)
	}
	if n := env.count(t, `SELECT count(*) FROM target_probe_jobs WHERE asset_id = $1`, assetID); n != 2 {
		t.Fatalf("probe jobs = %d; want 2 (onboarding + endpoint_changed)", n)
	}
}

// TestUpdatePostgresAssetMetadataOnlyPreservesRevision covers req 4 for postgres: a
// non-address change (default database + rotated secret, same target) leaves the
// endpoint revision untouched, queues no new probe, and keeps existing anchors current.
func TestUpdatePostgresAssetMetadataOnlyPreservesRevision(t *testing.T) {
	env := newCatalogTestEnv(t)
	folderID := env.createFolder(t, "prod")
	assetID := env.createPGAsset(t, folderID, "pgbox", []byte("s3cr3t")) // 10.0.0.9:5432, rev 1
	env.seedPGMigrationAnchor(t, assetID)

	// Same target address, changed default database + rotated login secret.
	env.updatePGConfig(t, assetID, "10.0.0.9:5432", "otherdb", []byte("rotated"))

	if rev := env.endpointRevision(t, assetID); rev != 1 {
		t.Fatalf("endpoint revision = %d; want 1 preserved on a metadata/login-only change", rev)
	}
	if n := env.currentAnchorCount(t, assetID); n != 1 {
		t.Fatalf("current anchors = %d; want 1 (unchanged endpoint keeps anchors valid)", n)
	}
	if n := env.count(t, `SELECT count(*) FROM target_probe_jobs WHERE asset_id = $1`, assetID); n != 1 {
		t.Fatalf("probe jobs = %d; want 1 (no new probe on a metadata/login-only change)", n)
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
