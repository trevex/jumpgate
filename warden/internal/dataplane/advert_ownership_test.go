package dataplane

import (
	"encoding/pem"
	"testing"
	"time"

	"github.com/google/uuid"

	dataplanev1 "github.com/trevex/jumpgate/warden/gen/jumpgate/dataplane/v1"
	"github.com/trevex/jumpgate/warden/internal/ca"
)

// meshLeafDER mints an agent (or other-role) mesh leaf under caPEM and returns its
// DER — the shape a broker relays in an advertisement.
func meshLeafDER(t *testing.T, spiffe string) (der []byte, caPEM []byte) {
	t.Helper()
	caKeyDER, caCertPEM, err := ca.GenerateMeshCA()
	if err != nil {
		t.Fatal(err)
	}
	return signLeafUnder(t, caKeyDER, caCertPEM, spiffe), caCertPEM
}

func signLeafUnder(t *testing.T, caKeyDER, caCertPEM []byte, spiffe string) []byte {
	t.Helper()
	mca, err := ca.LoadMeshCA(caKeyDER, caCertPEM)
	if err != nil {
		t.Fatal(err)
	}
	_, csrDER, err := ca.GenerateCSR(spiffe)
	if err != nil {
		t.Fatal(err)
	}
	leafPEM, _, err := mca.SignCSR(csrDER, spiffe, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(leafPEM)
	if block == nil {
		t.Fatal("no PEM block in signed leaf")
	}
	return block.Bytes
}

// TestAdvertisedAssetsDerivedFromAgentCert is the invariant-1 proof: warden derives
// the advertised asset id from the agent's verified mesh cert SAN and ignores the
// broker's bare asset_ids. A binding for asset A can never cause asset B to be
// advertised, and a cert warden's mesh CA did not sign is rejected outright.
func TestAdvertisedAssetsDerivedFromAgentCert(t *testing.T) {
	assetA := uuid.NewString()
	agentDER, caPEM := meshLeafDER(t, "spiffe://jumpgate/agent/"+assetA)
	h := NewHandler(nil, nil, nil, nil, nil, nil, caPEM)

	// A valid agent-A cert, but the broker lies and also claims asset "B" in the bare
	// list. Warden must advertise ONLY A (derived from the cert), never B.
	got := h.verifiedAdvertisedAssets(&dataplanev1.AdvertiseTunnels{
		AssetIds: []string{"asset-B-forged", assetA},
		Agents:   []*dataplanev1.AgentBinding{{AgentCertDer: agentDER}},
	})
	if len(got) != 1 || got[0] != assetA {
		t.Fatalf("verifiedAdvertisedAssets = %v, want [%s]", got, assetA)
	}

	// A cert signed by a DIFFERENT mesh CA (a broker forging its own) is rejected.
	foreignDER, _ := meshLeafDER(t, "spiffe://jumpgate/agent/"+uuid.NewString())
	if got := h.verifiedAdvertisedAssets(&dataplanev1.AdvertiseTunnels{
		Agents: []*dataplanev1.AgentBinding{{AgentCertDer: foreignDER}},
	}); len(got) != 0 {
		t.Fatalf("foreign-CA agent cert must be rejected, got %v", got)
	}

	// A valid-CA cert whose SAN is a non-agent role is rejected (only agents own tunnels).
	caKeyDER, caCertPEM, err := ca.GenerateMeshCA()
	if err != nil {
		t.Fatal(err)
	}
	workerDER := signLeafUnder(t, caKeyDER, caCertPEM, "spiffe://jumpgate/worker/ssh-0")
	hWorkerCA := NewHandler(nil, nil, nil, nil, nil, nil, caCertPEM)
	if got := hWorkerCA.verifiedAdvertisedAssets(&dataplanev1.AdvertiseTunnels{
		Agents: []*dataplanev1.AgentBinding{{AgentCertDer: workerDER}},
	}); len(got) != 0 {
		t.Fatalf("non-agent role cert must be rejected, got %v", got)
	}

	// An advertisement with no agent certs (only a bare asset_ids list) is dropped —
	// fail-closed against an old/compromised broker that omits the proof.
	if got := h.verifiedAdvertisedAssets(&dataplanev1.AdvertiseTunnels{AssetIds: []string{assetA}}); len(got) != 0 {
		t.Fatalf("bare asset_ids without agent certs must be dropped, got %v", got)
	}
}

// TestAdvertisedAssetsFailClosedWithoutMeshCA proves that without a mesh CA warden
// verifies nothing and advertises nothing.
func TestAdvertisedAssetsFailClosedWithoutMeshCA(t *testing.T) {
	agentDER, _ := meshLeafDER(t, "spiffe://jumpgate/agent/"+uuid.NewString())
	h := NewHandler(nil, nil, nil, nil, nil, nil, nil) // no mesh CA configured
	if got := h.verifiedAdvertisedAssets(&dataplanev1.AdvertiseTunnels{
		Agents: []*dataplanev1.AgentBinding{{AgentCertDer: agentDER}},
	}); len(got) != 0 {
		t.Fatalf("no-mesh-CA handler must advertise nothing, got %v", got)
	}
}
