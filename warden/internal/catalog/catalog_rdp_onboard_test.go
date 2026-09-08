package catalog_test

import (
	"context"
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

// updateRDPConfig drives UpdateAssetConfig for an rdp asset with the given target
// address (admin password login with a rotated secret, matching createRDPAsset's
// login set), exercising the rdp create/update probe hooks.
func (e *catalogTestEnv) updateRDPConfig(t *testing.T, assetID, targetAddress string, secret []byte) {
	t.Helper()
	_, err := e.catalog.UpdateAssetConfig(e.adminCtx, connect.NewRequest(&catalogv1.UpdateAssetConfigRequest{
		AssetId: assetID,
		Config: &catalogv1.UpdateAssetConfigRequest_Rdp{Rdp: &catalogv1.RDPConfigInput{
			TargetAddress: targetAddress,
			Logins: []*catalogv1.RDPLoginInput{
				{Login: "admin", Auth: &catalogv1.RDPLoginInput_Password{Password: &catalogv1.SecretAuth{
					Source: &catalogv1.SecretAuth_NewValue{NewValue: secret}}}},
			},
		}},
	}))
	if err != nil {
		t.Fatalf("UpdateAssetConfig(rdp): %v", err)
	}
}

// seedRDPMigrationAnchor inserts an approved migration-source tls_ca anchor at the
// asset's current revision, standing in for trust the rdp migration established.
func (e *catalogTestEnv) seedRDPMigrationAnchor(t *testing.T, assetID string) {
	t.Helper()
	if _, err := e.pool.Exec(context.Background(), `
		INSERT INTO target_trust_anchors (asset_id, endpoint_revision, kind, algorithm, sha256_fingerprint, public_material, source, required_dns_names)
		SELECT id, endpoint_revision, 'tls_ca', 'ecdsa', 'SHA256:rdp-seeded', 'ca-pem', 'migration', ARRAY['10.0.0.20']
		FROM assets WHERE id = $1`, assetID); err != nil {
		t.Fatalf("seed rdp migration anchor: %v", err)
	}
}

// TestCreateRDPAssetQueuesOnboardingProbe covers correctness req 5 for rdp: a created
// rdp asset persists at revision 1 and gets exactly one queued onboarding probe at
// that same revision (protocol rdp), in one logical operation.
func TestCreateRDPAssetQueuesOnboardingProbe(t *testing.T) {
	env := newCatalogTestEnv(t)
	folderID := env.createFolder(t, "desktops")
	assetID := env.createRDPAsset(t, folderID, "workstation", []byte("s3cr3t")) // 10.0.0.20:3389, rev 1

	if rev := env.endpointRevision(t, assetID); rev != 1 {
		t.Fatalf("endpoint revision = %d; want 1", rev)
	}
	var rev int64
	var protocol, reason, state string
	if err := env.pool.QueryRow(context.Background(),
		`SELECT endpoint_revision, protocol, reason, state FROM target_probe_jobs WHERE asset_id = $1`, assetID).Scan(&rev, &protocol, &reason, &state); err != nil {
		t.Fatalf("read probe job: %v", err)
	}
	if rev != 1 || protocol != "rdp" || reason != "onboarding" || state != "queued" {
		t.Fatalf("probe job rev=%d protocol=%q reason=%q state=%q; want 1/rdp/onboarding/queued", rev, protocol, reason, state)
	}
	if n := env.count(t, `SELECT count(*) FROM target_probe_jobs WHERE asset_id = $1`, assetID); n != 1 {
		t.Fatalf("probe jobs = %d; want exactly 1", n)
	}
}

// TestUpdateRDPAssetAddressChangeIncrementsRevisionAndQueuesProbe covers req 3 for
// rdp: a target-address change increments the endpoint revision (invalidating old
// anchors) and queues a fresh probe at the new revision.
func TestUpdateRDPAssetAddressChangeIncrementsRevisionAndQueuesProbe(t *testing.T) {
	env := newCatalogTestEnv(t)
	folderID := env.createFolder(t, "desktops")
	assetID := env.createRDPAsset(t, folderID, "workstation", []byte("s3cr3t")) // 10.0.0.20:3389, rev 1
	env.seedRDPMigrationAnchor(t, assetID)
	if n := env.currentAnchorCount(t, assetID); n != 1 {
		t.Fatalf("seeded current anchors = %d; want 1", n)
	}

	env.updateRDPConfig(t, assetID, "10.0.0.21:3389", []byte("s3cr3t"))

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

// TestUpdateRDPAssetLoginOnlyPreservesRevision covers req 4 for rdp: a non-address
// change (rotated login secret, same target) leaves the endpoint revision untouched,
// queues no new probe, and keeps existing anchors current.
func TestUpdateRDPAssetLoginOnlyPreservesRevision(t *testing.T) {
	env := newCatalogTestEnv(t)
	folderID := env.createFolder(t, "desktops")
	assetID := env.createRDPAsset(t, folderID, "workstation", []byte("s3cr3t")) // 10.0.0.20:3389, rev 1
	env.seedRDPMigrationAnchor(t, assetID)

	// Same target address, rotated login secret only.
	env.updateRDPConfig(t, assetID, "10.0.0.20:3389", []byte("rotated"))

	if rev := env.endpointRevision(t, assetID); rev != 1 {
		t.Fatalf("endpoint revision = %d; want 1 preserved on a login-only change", rev)
	}
	if n := env.currentAnchorCount(t, assetID); n != 1 {
		t.Fatalf("current anchors = %d; want 1 (unchanged endpoint keeps anchors valid)", n)
	}
	if n := env.count(t, `SELECT count(*) FROM target_probe_jobs WHERE asset_id = $1`, assetID); n != 1 {
		t.Fatalf("probe jobs = %d; want 1 (no new probe on a login-only change)", n)
	}
}
