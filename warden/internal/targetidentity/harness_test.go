package targetidentity_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	pgxuuid "github.com/vgarvardt/pgx-google-uuid/v5"

	"github.com/trevex/jumpgate/warden/internal/audit"
	"github.com/trevex/jumpgate/warden/internal/postgres/migrate"
	"github.com/trevex/jumpgate/warden/internal/postgres/sqlc"
	"github.com/trevex/jumpgate/warden/internal/targetidentity"
	"github.com/trevex/jumpgate/warden/internal/testsupport"
)

var testPool *pgxpool.Pool

var errAuditRejected = errors.New("audit rejected")

type failingEnqueuer struct{}

func (failingEnqueuer) Enqueue(context.Context, *sqlc.Queries, audit.Event) error {
	return errAuditRejected
}

func TestMain(m *testing.M) {
	dsn, stop, err := testsupport.StartPostgresProcess()
	if err != nil {
		fmt.Fprintf(os.Stderr, "targetidentity: start postgres: %v\n", err)
		os.Exit(1)
	}
	defer stop()
	if err := migrate.Up(dsn); err != nil {
		fmt.Fprintf(os.Stderr, "targetidentity: migrate: %v\n", err)
		os.Exit(1)
	}
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		fmt.Fprintf(os.Stderr, "targetidentity: parse config: %v\n", err)
		os.Exit(1)
	}
	cfg.AfterConnect = func(_ context.Context, conn *pgx.Conn) error {
		pgxuuid.Register(conn.TypeMap())
		return nil
	}
	testPool, err = pgxpool.NewWithConfig(context.Background(), cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "targetidentity: pool: %v\n", err)
		os.Exit(1)
	}
	code := m.Run()
	testPool.Close()
	os.Exit(code)
}

type targetIdentityEnv struct {
	t      *testing.T
	ctx    context.Context
	q      *sqlc.Queries
	svc    *targetidentity.Service
	asset  uuid.UUID
	actor  uuid.UUID
	worker string
}

func newTargetIdentityEnv(t *testing.T) *targetIdentityEnv {
	return newTargetIdentityEnvForProtocol(t, targetidentity.ProtocolSSH)
}

func newTargetIdentityEnvForProtocol(t *testing.T, protocol targetidentity.Protocol) *targetIdentityEnv {
	t.Helper()
	ctx := context.Background()
	q := sqlc.New(testPool)
	actorID := uuid.New()
	if _, err := testPool.Exec(ctx, `INSERT INTO users (id, email, display_name, password_hash) VALUES ($1,$2,$3,'x')`, actorID, actorID.String()+"@example.test", "identity operator"); err != nil {
		t.Fatalf("insert actor: %v", err)
	}
	folder, err := q.CreateFolder(ctx, sqlc.CreateFolderParams{Name: "ti-" + uuid.NewString()})
	if err != nil {
		t.Fatalf("create folder: %v", err)
	}
	asset, err := q.CreateAsset(ctx, sqlc.CreateAssetParams{FolderID: folder.ID, Name: "host", Labels: []byte("{}"), Kind: string(protocol)})
	if err != nil {
		t.Fatalf("create asset: %v", err)
	}
	switch protocol {
	case targetidentity.ProtocolSSH:
		_, err = testPool.Exec(ctx, `INSERT INTO ssh_asset_config (asset_id,target_address,host_public_key) VALUES ($1,'host.test:22','')`, asset.ID)
	case targetidentity.ProtocolPostgres:
		_, err = testPool.Exec(ctx, `INSERT INTO postgres_asset_config (asset_id,target_address,target_server_ca,default_database) VALUES ($1,'db.test:5432','','postgres')`, asset.ID)
	default:
		t.Fatalf("test protocol %q is not supported by the harness", protocol)
	}
	if err != nil {
		t.Fatalf("insert %s config: %v", protocol, err)
	}
	return &targetIdentityEnv{
		t:      t,
		ctx:    ctx,
		q:      q,
		svc:    targetidentity.NewService(testPool, audit.New(testPool)),
		asset:  asset.ID,
		actor:  actorID,
		worker: "spiffe://jumpgate.test/worker/" + uuid.NewString(),
	}
}

func fingerprint(label string) string {
	sum := sha256.Sum256([]byte(label))
	return "SHA256:" + base64.RawStdEncoding.EncodeToString(sum[:])
}

func testCAPEM(t *testing.T, label string) (string, string) {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate CA key: %v", err)
	}
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: label},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, publicKey, privateKey)
	if err != nil {
		t.Fatalf("create CA certificate: %v", err)
	}
	sum := sha256.Sum256(der)
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), "SHA256:" + base64.RawStdEncoding.EncodeToString(sum[:])
}

func sshEvidence(label string) targetidentity.Evidence {
	return targetidentity.Evidence{
		Kind:           targetidentity.EvidenceSSHHostKey,
		Algorithm:      "ssh-ed25519",
		Fingerprint:    fingerprint(label),
		PublicMaterial: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI" + label,
	}
}

func (e *targetIdentityEnv) queue(t *testing.T, reason targetidentity.ProbeReason, previous uuid.UUID) targetidentity.ProbeJob {
	t.Helper()
	job, err := e.svc.QueueProbe(e.ctx, targetidentity.QueueProbeRequest{
		AssetID:          e.asset,
		EndpointRevision: 1,
		Reason:           reason,
		RequestedBy:      e.actor,
		PreviousJobID:    previous,
		MaxAttempts:      3,
	})
	if err != nil {
		t.Fatalf("queue probe: %v", err)
	}
	return job
}

func (e *targetIdentityEnv) complete(t *testing.T, evidence ...targetidentity.Evidence) targetidentity.VerificationStatus {
	t.Helper()
	e.queue(t, targetidentity.ProbeReasonOnboarding, uuid.Nil)
	return e.claimAndComplete(t, targetidentity.ProbeSucceeded, "", evidence...)
}

func (e *targetIdentityEnv) claimAndComplete(t *testing.T, outcome targetidentity.ProbeOutcome, category targetidentity.FailureCategory, evidence ...targetidentity.Evidence) targetidentity.VerificationStatus {
	t.Helper()
	lease, err := e.svc.Claim(e.ctx, targetidentity.ClaimRequest{WorkerID: e.worker, Protocol: targetidentity.ProtocolSSH})
	if err != nil {
		t.Fatalf("claim: %v", err)
	}
	status, err := e.svc.Complete(e.ctx, targetidentity.CompleteRequest{
		JobID:      lease.JobID,
		WorkerID:   e.worker,
		LeaseToken: lease.Token,
		Result: targetidentity.ProbeResult{
			Outcome:           outcome,
			FailureCategory:   category,
			ResolvedAddresses: []string{"192.0.2.10"},
			SSH:               &targetidentity.SSHMetadata{Banner: "SSH-2.0-test"},
			Evidence:          evidence,
		},
	})
	if err != nil {
		t.Fatalf("complete: %v", err)
	}
	return status
}

func (e *targetIdentityEnv) approve(t *testing.T, observationID uuid.UUID, fp string, expiresAt time.Time) targetidentity.TrustAnchor {
	t.Helper()
	var evidenceID uuid.UUID
	for _, evidence := range e.evidence(t) {
		if evidence.ObservationID == observationID && evidence.Fingerprint == fp {
			evidenceID = evidence.ID
			break
		}
	}
	if evidenceID == uuid.Nil {
		t.Fatalf("evidence %q for observation %s not found", fp, observationID)
	}
	anchor, _, err := e.svc.Approve(e.ctx, targetidentity.ApproveRequest{
		AssetID:             e.asset,
		ExpectedRevision:    1,
		ObservationID:       observationID,
		EvidenceID:          evidenceID,
		SelectedFingerprint: fp,
		Source:              targetidentity.TrustSourceManual,
		ActorID:             e.actor,
		ExpiresAt:           expiresAt,
	})
	if err != nil {
		t.Fatalf("approve: %v", err)
	}
	return anchor
}

func (e *targetIdentityEnv) evidence(t *testing.T) []targetidentity.Evidence {
	t.Helper()
	items, err := e.svc.ListEvidence(e.ctx, e.asset, 1)
	if err != nil {
		t.Fatalf("list evidence: %v", err)
	}
	return items
}

func (e *targetIdentityEnv) status(t *testing.T) targetidentity.VerificationStatus {
	t.Helper()
	status, err := e.svc.Status(e.ctx, targetidentity.StatusRequest{AssetID: e.asset})
	if err != nil {
		t.Fatalf("status: %v", err)
	}
	return status
}
