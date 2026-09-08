package catalog_test

import (
	"context"
	"testing"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	catalogv1 "github.com/trevex/jumpgate/warden/gen/jumpgate/catalog/v1"
	"github.com/trevex/jumpgate/warden/internal/apiguard"
	"github.com/trevex/jumpgate/warden/internal/audit"
	"github.com/trevex/jumpgate/warden/internal/auth"
	"github.com/trevex/jumpgate/warden/internal/authz"
	"github.com/trevex/jumpgate/warden/internal/catalog"
	"github.com/trevex/jumpgate/warden/internal/postgres/sqlc"
	"github.com/trevex/jumpgate/warden/internal/targetidentity"
)

// catalogTestEnv is an in-process catalog Handler wired with a real pgx pool, a real
// sealer (so inline-secret sealing is exercised), and an admin-capability context.
type catalogTestEnv struct {
	catalog  *catalog.Handler
	adminCtx context.Context
	pool     *pgxpool.Pool
	userID   uuid.UUID
}

// newCatalogTestEnv builds a CatalogServer over an ephemeral Postgres, seeds a
// bootstrap admin (holds ** → every management cap), and returns an env whose
// adminCtx carries that admin. The sealer is the shared test sealer so onboarding
// can seal inline login secrets.
func newCatalogTestEnv(t *testing.T) *catalogTestEnv {
	t.Helper()
	// Reuse newServer's pool + migrations; we only need the pool (the wire URL is
	// unused because we drive the server in-process).
	pool, _ := newServer(t)
	seedUser(t, pool, "admin@x", "supersecret", true)

	q := sqlc.New(pool)
	authorizer := authz.New(pool)
	probes := targetidentity.NewService(pool, audit.New(pool))
	srv := catalog.NewHandler(catalog.NewService(pool, testSealer(t), nil, authorizer, nil, probes), apiguard.New(authorizer, q))

	adminID := userID(t, pool, "admin@x")
	adminCtx := auth.WithUser(context.Background(), auth.CurrentUser{ID: adminID, Email: "admin@x"})
	return &catalogTestEnv{catalog: srv, adminCtx: adminCtx, pool: pool, userID: adminID}
}

// createFolder creates a top-level folder and returns its id.
func (e *catalogTestEnv) createFolder(t *testing.T, name string) string {
	t.Helper()
	f, err := e.catalog.CreateFolder(e.adminCtx, connect.NewRequest(&catalogv1.CreateFolderRequest{Name: name}))
	if err != nil {
		t.Fatalf("createFolder(%q): %v", name, err)
	}
	return f.Msg.Folder.Id
}

// createChildFolder creates a folder under parentID and returns its id.
func (e *catalogTestEnv) createChildFolder(t *testing.T, name, parentID string) string {
	t.Helper()
	f, err := e.catalog.CreateFolder(e.adminCtx, connect.NewRequest(&catalogv1.CreateFolderRequest{Name: name, ParentId: parentID}))
	if err != nil {
		t.Fatalf("createChildFolder(%q under %q): %v", name, parentID, err)
	}
	return f.Msg.Folder.Id
}

// createSSHAsset onboards an SSH asset under folderID with a ca login "deploy" and a
// password login named login carrying secret as an inline new_value; returns the id.
func (e *catalogTestEnv) createSSHAsset(t *testing.T, folderID, name, login string, secret []byte) string {
	t.Helper()
	resp, err := e.catalog.CreateAsset(e.adminCtx, connect.NewRequest(&catalogv1.CreateAssetRequest{
		FolderId: folderID,
		Name:     name,
		Config: &catalogv1.CreateAssetRequest_Ssh{Ssh: &catalogv1.SSHConfigInput{
			TargetAddress: "10.0.0.5:22",
			Logins: []*catalogv1.SSHLoginInput{
				{Login: "deploy", Auth: &catalogv1.SSHLoginInput_Ca{Ca: &catalogv1.CaAuth{}}},
				{Login: login, Auth: &catalogv1.SSHLoginInput_Password{Password: &catalogv1.SecretAuth{
					Source: &catalogv1.SecretAuth_NewValue{NewValue: secret}}}},
			},
		}},
	}))
	if err != nil {
		t.Fatalf("createSSHAsset(%q): %v", name, err)
	}
	return resp.Msg.Asset.Id
}

// bindRoleToAsset inserts a role and a standing role_binding scoped to assetID with the
// seeded admin as the subject, so DeleteAsset has an asset-scoped binding to cascade.
func (e *catalogTestEnv) bindRoleToAsset(t *testing.T, assetID string) {
	t.Helper()
	var roleID string
	if err := e.pool.QueryRow(context.Background(),
		`INSERT INTO roles(name) VALUES('r-'||substr(md5(random()::text),1,8)) RETURNING id`,
	).Scan(&roleID); err != nil {
		t.Fatalf("insert role: %v", err)
	}
	if _, err := e.pool.Exec(context.Background(),
		`INSERT INTO role_bindings(role_id, scope_asset_id, subject_user_id) VALUES($1, $2, $3)`,
		roleID, assetID, e.userID,
	); err != nil {
		t.Fatalf("insert role_binding: %v", err)
	}
}

// count runs a single-int aggregate query on the env pool.
func (e *catalogTestEnv) count(t *testing.T, query string, args ...any) int {
	t.Helper()
	var n int
	if err := e.pool.QueryRow(context.Background(), query, args...).Scan(&n); err != nil {
		t.Fatalf("count %q: %v", query, err)
	}
	return n
}

func TestCreateAssetInlineSecretsAtomic(t *testing.T) {
	env := newCatalogTestEnv(t)
	folderID := env.createFolder(t, "prod")

	resp, err := env.catalog.CreateAsset(env.adminCtx, connect.NewRequest(&catalogv1.CreateAssetRequest{
		FolderId: folderID,
		Name:     "pg",
		Config: &catalogv1.CreateAssetRequest_Ssh{Ssh: &catalogv1.SSHConfigInput{
			TargetAddress: "10.0.0.5:22",
			Logins: []*catalogv1.SSHLoginInput{
				{Login: "deploy", Auth: &catalogv1.SSHLoginInput_Ca{Ca: &catalogv1.CaAuth{}}},
				{Login: "app", Auth: &catalogv1.SSHLoginInput_Password{Password: &catalogv1.SecretAuth{
					Source: &catalogv1.SecretAuth_NewValue{NewValue: []byte("s3cr3t")}}}},
			},
		}},
	}))
	if err != nil {
		t.Fatalf("CreateAsset: %v", err)
	}
	assetID := resp.Msg.Asset.Id

	got, err := env.catalog.GetAsset(env.adminCtx, connect.NewRequest(&catalogv1.GetAssetRequest{AssetId: assetID}))
	if err != nil {
		t.Fatalf("GetAsset: %v", err)
	}
	if got.Msg.Asset.Kind != "ssh" {
		t.Fatalf("kind = %q, want ssh", got.Msg.Asset.Kind)
	}
	logins := got.Msg.Asset.GetSsh().GetLogins()
	if len(logins) != 2 {
		t.Fatalf("logins = %d, want 2", len(logins))
	}
	var app *catalogv1.SSHLogin
	for _, l := range logins {
		if l.Login == "app" {
			app = l
		}
	}
	if app == nil || app.Kind != "password" || app.SecretId == "" {
		t.Fatalf("app login = %+v, want kind=password with a secret_id", app)
	}
}

// endpointRevision reads an asset's current endpoint revision.
func (e *catalogTestEnv) endpointRevision(t *testing.T, assetID string) int64 {
	t.Helper()
	var rev int64
	if err := e.pool.QueryRow(context.Background(), `SELECT endpoint_revision FROM assets WHERE id = $1`, assetID).Scan(&rev); err != nil {
		t.Fatalf("read endpoint revision: %v", err)
	}
	return rev
}

// updateSSHConfig drives the handler's UpdateAssetConfig with a single ca login and
// the given target address, exercising the create/update probe + revision hooks.
func (e *catalogTestEnv) updateSSHConfig(t *testing.T, assetID, targetAddress string, secret []byte) {
	t.Helper()
	_, err := e.catalog.UpdateAssetConfig(e.adminCtx, connect.NewRequest(&catalogv1.UpdateAssetConfigRequest{
		AssetId: assetID,
		Config: &catalogv1.UpdateAssetConfigRequest_Ssh{Ssh: &catalogv1.SSHConfigInput{
			TargetAddress: targetAddress,
			Logins: []*catalogv1.SSHLoginInput{
				{Login: "deploy", Auth: &catalogv1.SSHLoginInput_Ca{Ca: &catalogv1.CaAuth{}}},
				{Login: "app", Auth: &catalogv1.SSHLoginInput_Password{Password: &catalogv1.SecretAuth{
					Source: &catalogv1.SecretAuth_NewValue{NewValue: secret}}}},
			},
		}},
	}))
	if err != nil {
		t.Fatalf("UpdateAssetConfig: %v", err)
	}
}

// seedMigrationAnchor inserts an approved migration-source anchor at the asset's
// current revision, standing in for trust the migration established.
func (e *catalogTestEnv) seedMigrationAnchor(t *testing.T, assetID string) {
	t.Helper()
	if _, err := e.pool.Exec(context.Background(), `
		INSERT INTO target_trust_anchors (asset_id, endpoint_revision, kind, algorithm, sha256_fingerprint, public_material, source)
		SELECT id, endpoint_revision, 'ssh_host_key', 'ssh-ed25519', 'SHA256:seeded', 'ssh-ed25519 AAAA', 'migration'
		FROM assets WHERE id = $1`, assetID); err != nil {
		t.Fatalf("seed migration anchor: %v", err)
	}
}

// currentAnchorCount counts anchors that are current (matching the asset's live
// endpoint revision) and not revoked — the set a session would verify against.
func (e *catalogTestEnv) currentAnchorCount(t *testing.T, assetID string) int {
	t.Helper()
	return e.count(t, `
		SELECT count(*) FROM target_trust_anchors a
		JOIN assets s ON s.id = a.asset_id AND s.endpoint_revision = a.endpoint_revision
		WHERE a.asset_id = $1 AND a.revoked_at IS NULL`, assetID)
}

// TestCreateSSHAssetQueuesOnboardingProbe covers correctness req 5: a created SSH
// asset persists at revision 1 and gets exactly one queued onboarding probe at that
// same revision, in one logical operation.
func TestCreateSSHAssetQueuesOnboardingProbe(t *testing.T) {
	env := newCatalogTestEnv(t)
	folderID := env.createFolder(t, "prod")
	assetID := env.createSSHAsset(t, folderID, "h", "app", []byte("s3cr3t"))

	if rev := env.endpointRevision(t, assetID); rev != 1 {
		t.Fatalf("endpoint revision = %d; want 1", rev)
	}
	var rev int64
	var reason, state string
	if err := env.pool.QueryRow(context.Background(),
		`SELECT endpoint_revision, reason, state FROM target_probe_jobs WHERE asset_id = $1`, assetID).Scan(&rev, &reason, &state); err != nil {
		t.Fatalf("read probe job: %v", err)
	}
	if rev != 1 || reason != "onboarding" || state != "queued" {
		t.Fatalf("probe job rev=%d reason=%q state=%q; want 1/onboarding/queued", rev, reason, state)
	}
	if n := env.count(t, `SELECT count(*) FROM target_probe_jobs WHERE asset_id = $1`, assetID); n != 1 {
		t.Fatalf("probe jobs = %d; want exactly 1", n)
	}
}

// TestUpdateSSHAssetAddressChangeIncrementsRevisionAndQueuesProbe covers req 3: a
// target-address change increments the endpoint revision (invalidating old anchors)
// and queues a fresh probe at the new revision.
func TestUpdateSSHAssetAddressChangeIncrementsRevisionAndQueuesProbe(t *testing.T) {
	env := newCatalogTestEnv(t)
	folderID := env.createFolder(t, "prod")
	assetID := env.createSSHAsset(t, folderID, "h", "app", []byte("s3cr3t")) // 10.0.0.5:22, rev 1, onboarding probe
	env.seedMigrationAnchor(t, assetID)
	if n := env.currentAnchorCount(t, assetID); n != 1 {
		t.Fatalf("seeded current anchors = %d; want 1", n)
	}

	env.updateSSHConfig(t, assetID, "10.0.0.9:22", []byte("s3cr3t"))

	if rev := env.endpointRevision(t, assetID); rev != 2 {
		t.Fatalf("endpoint revision = %d; want 2 after target-address change", rev)
	}
	// The old anchor is stranded at revision 1 and is no longer current.
	if n := env.currentAnchorCount(t, assetID); n != 0 {
		t.Fatalf("current anchors after endpoint change = %d; want 0 (old anchors invalidated)", n)
	}
	var rev int64
	var reason string
	if err := env.pool.QueryRow(context.Background(),
		`SELECT endpoint_revision, reason FROM target_probe_jobs WHERE asset_id = $1 AND reason = 'endpoint_changed'`, assetID).Scan(&rev, &reason); err != nil {
		t.Fatalf("read endpoint_changed probe: %v", err)
	}
	if rev != 2 {
		t.Fatalf("endpoint_changed probe revision = %d; want 2", rev)
	}
	if n := env.count(t, `SELECT count(*) FROM target_probe_jobs WHERE asset_id = $1`, assetID); n != 2 {
		t.Fatalf("probe jobs = %d; want 2 (onboarding + endpoint_changed)", n)
	}
}

// TestUpdateSSHAssetLoginOnlyPreservesRevision covers req 4: a login/secret-only
// change (same target address) leaves the endpoint revision untouched, queues no new
// probe, and keeps existing anchors current.
func TestUpdateSSHAssetLoginOnlyPreservesRevision(t *testing.T) {
	env := newCatalogTestEnv(t)
	folderID := env.createFolder(t, "prod")
	assetID := env.createSSHAsset(t, folderID, "h", "app", []byte("s3cr3t")) // 10.0.0.5:22, rev 1
	env.seedMigrationAnchor(t, assetID)

	// Same target address, rotated login secret only.
	env.updateSSHConfig(t, assetID, "10.0.0.5:22", []byte("rotated"))

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

func TestCreateAssetRejectsEmptyInlineSecret(t *testing.T) {
	env := newCatalogTestEnv(t)
	folderID := env.createFolder(t, "prod")
	_, err := env.catalog.CreateAsset(env.adminCtx, connect.NewRequest(&catalogv1.CreateAssetRequest{
		FolderId: folderID, Name: "pg",
		Config: &catalogv1.CreateAssetRequest_Ssh{Ssh: &catalogv1.SSHConfigInput{Logins: []*catalogv1.SSHLoginInput{
			{Login: "app", Auth: &catalogv1.SSHLoginInput_Password{Password: &catalogv1.SecretAuth{
				Source: &catalogv1.SecretAuth_NewValue{NewValue: []byte{}}}}},
		}}},
	}))
	if connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Fatalf("want InvalidArgument for empty new_value, got %v", err)
	}
}

func TestCreateAssetRejectsExistingSecretId(t *testing.T) {
	env := newCatalogTestEnv(t)
	folderID := env.createFolder(t, "prod")
	_, err := env.catalog.CreateAsset(env.adminCtx, connect.NewRequest(&catalogv1.CreateAssetRequest{
		FolderId: folderID, Name: "pg",
		Config: &catalogv1.CreateAssetRequest_Ssh{Ssh: &catalogv1.SSHConfigInput{Logins: []*catalogv1.SSHLoginInput{
			{Login: "app", Auth: &catalogv1.SSHLoginInput_Password{Password: &catalogv1.SecretAuth{
				Source: &catalogv1.SecretAuth_ExistingSecretId{ExistingSecretId: uuid.NewString()}}}},
		}}},
	}))
	if connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Fatalf("want InvalidArgument for existing_secret_id on create, got %v", err)
	}
}
