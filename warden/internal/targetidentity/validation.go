package targetidentity

import (
	"crypto/sha256"
	"encoding/base64"
	"net"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
)

func validateResult(result ProbeResult, now time.Time) error {
	if result.Outcome != ProbeSucceeded && result.Outcome != ProbeFailed {
		return ErrInvalidResult
	}
	if len(result.ResolvedAddresses) > MaxResolvedAddresses || len(result.Evidence) > MaxEvidenceCount || len(result.FailureDetail) > MaxFailureDetailBytes || !utf8.ValidString(result.FailureDetail) {
		return ErrInvalidResult
	}
	if result.Outcome == ProbeSucceeded && (len(result.Evidence) == 0 || result.FailureCategory != "") {
		return ErrInvalidResult
	}
	if result.Outcome == ProbeFailed && !validFailureCategory(result.FailureCategory) {
		return ErrInvalidResult
	}
	for _, address := range result.ResolvedAddresses {
		if net.ParseIP(address) == nil {
			return ErrInvalidResult
		}
	}
	if !validMetadata(result) {
		return ErrInvalidResult
	}
	seen := make(map[string]struct{}, len(result.Evidence))
	for _, item := range result.Evidence {
		if !validEvidence(item, now) {
			return ErrInvalidResult
		}
		key := string(item.Kind) + "\x00" + item.Fingerprint
		if _, exists := seen[key]; exists {
			return ErrInvalidResult
		}
		seen[key] = struct{}{}
	}
	if len(result.ValidationFacts) > MaxEvidenceCount {
		return ErrInvalidResult
	}
	for _, fact := range result.ValidationFacts {
		if fact.AnchorID == uuid.Nil || !validEvidenceKind(fact.EvidenceKind) || !validFingerprint(fact.EvidenceFingerprint) {
			return ErrInvalidResult
		}
	}
	return nil
}

func validEvidence(item Evidence, _ time.Time) bool {
	if !validEvidenceKind(item.Kind) || item.Algorithm == "" || len(item.Algorithm) > MaxNameBytes || !utf8.ValidString(item.Algorithm) || !validFingerprint(item.Fingerprint) || len(item.PublicMaterial) == 0 || len(item.PublicMaterial) > MaxPublicMaterialBytes || !utf8.ValidString(item.PublicMaterial) {
		return false
	}
	if !validNames(item.DNSNames) || !validIPNames(item.IPAddresses) || !validNames(item.SSHPrincipals) || len(item.DisplayExtensions) > MaxExtensions {
		return false
	}
	if len(item.CertificateSubject) > MaxCertificateNameBytes || len(item.CertificateIssuer) > MaxCertificateNameBytes || len(item.SerialNumber) > MaxSerialNumberBytes || len(item.Key.Curve) > MaxKeyCurveBytes || item.Key.Bits < 0 || item.Key.Bits > MaxKeyBits || !utf8.ValidString(item.CertificateSubject+item.CertificateIssuer+item.SerialNumber+item.Key.Curve) || (item.IssuerFingerprint != "" && !validFingerprint(item.IssuerFingerprint)) {
		return false
	}
	for _, extension := range item.DisplayExtensions {
		if extension.Name == "" || len(extension.Name) > MaxNameBytes || len(extension.Value) > MaxMetadataTextBytes || !utf8.ValidString(extension.Name+extension.Value) {
			return false
		}
	}
	for i, extension := range item.DisplayExtensions {
		for _, previous := range item.DisplayExtensions[:i] {
			if extension.Name == previous.Name {
				return false
			}
		}
	}
	if item.Kind != EvidenceSSHHostKey {
		if item.ValidFrom.IsZero() || item.ValidUntil.IsZero() || !item.ValidUntil.After(item.ValidFrom) {
			return false
		}
	}
	return true
}

func validateProtocolResult(protocol Protocol, result ProbeResult) error {
	var allowedEvidence func(EvidenceKind) bool
	switch protocol {
	case ProtocolSSH:
		if result.TLS != nil || result.Kubernetes != nil {
			return ErrInvalidResult
		}
		allowedEvidence = func(kind EvidenceKind) bool {
			return kind == EvidenceSSHHostKey || kind == EvidenceSSHHostCertificate
		}
	case ProtocolPostgres, ProtocolRDP:
		if result.SSH != nil || result.Kubernetes != nil {
			return ErrInvalidResult
		}
		allowedEvidence = func(kind EvidenceKind) bool {
			return kind == EvidenceTLSLeaf || kind == EvidenceTLSIntermediate || kind == EvidenceTLSPresentedRoot
		}
	case ProtocolKubernetes:
		if result.SSH != nil || result.TLS != nil {
			return ErrInvalidResult
		}
		allowedEvidence = func(kind EvidenceKind) bool {
			return kind == EvidenceTLSLeaf || kind == EvidenceTLSIntermediate || kind == EvidenceTLSPresentedRoot
		}
	default:
		return ErrInvalidResult
	}
	for _, evidence := range result.Evidence {
		if !allowedEvidence(evidence.Kind) {
			return ErrInvalidResult
		}
	}
	return nil
}

func validMetadata(result ProbeResult) bool {
	count := 0
	if result.SSH != nil {
		count++
		if len(result.SSH.Banner) > MaxMetadataTextBytes || !utf8.ValidString(result.SSH.Banner) || !validNames(result.SSH.HostKeyAlgorithms) {
			return false
		}
	}
	if result.TLS != nil {
		count++
		for _, value := range []string{result.TLS.Version, result.TLS.CipherSuite, result.TLS.ServerName, result.TLS.ALPN} {
			if len(value) > MaxNameBytes || !utf8.ValidString(value) {
				return false
			}
		}
	}
	if result.Kubernetes != nil {
		count++
		if len(result.Kubernetes.APIServerName) > MaxNameBytes || !utf8.ValidString(result.Kubernetes.APIServerName) {
			return false
		}
	}
	return count <= 1
}

func validFingerprint(fingerprint string) bool {
	const prefix = "SHA256:"
	if !strings.HasPrefix(fingerprint, prefix) {
		return false
	}
	raw, err := base64.RawStdEncoding.DecodeString(strings.TrimPrefix(fingerprint, prefix))
	return err == nil && len(raw) == sha256.Size && prefix+base64.RawStdEncoding.EncodeToString(raw) == fingerprint
}

func validNames(values []string) bool {
	if len(values) > MaxNames {
		return false
	}
	for _, value := range values {
		if value == "" || len(value) > MaxNameBytes || !utf8.ValidString(value) {
			return false
		}
	}
	return true
}

func validIPNames(values []string) bool {
	if !validNames(values) {
		return false
	}
	for _, value := range values {
		if net.ParseIP(value) == nil {
			return false
		}
	}
	return true
}

func approvalKind(evidenceKind EvidenceKind, requested TrustAnchorKind) (TrustAnchorKind, error) {
	derived := TrustAnchorKind("")
	switch evidenceKind {
	case EvidenceSSHHostKey:
		derived = AnchorSSHHostKey
	case EvidenceTLSLeaf:
		derived = AnchorTLSLeaf
	case EvidenceTLSIntermediate, EvidenceTLSPresentedRoot:
		derived = AnchorTLSCA
	default:
		return "", ErrUnsupportedEvidence
	}
	if requested != "" && requested != derived {
		return "", ErrUnsupportedEvidence
	}
	return derived, nil
}

func anchorCompatibleWithProtocol(protocol Protocol, kind TrustAnchorKind) bool {
	switch protocol {
	case ProtocolSSH:
		return kind == AnchorSSHHostKey || kind == AnchorSSHHostCA
	case ProtocolPostgres, ProtocolRDP, ProtocolKubernetes:
		return kind == AnchorTLSLeaf || kind == AnchorTLSCA
	default:
		return false
	}
}

func validProtocol(value Protocol) bool {
	return value == ProtocolSSH || value == ProtocolPostgres || value == ProtocolRDP || value == ProtocolKubernetes
}

func validProbeReason(value ProbeReason) bool {
	return value == ProbeReasonOnboarding || value == ProbeReasonManual || value == ProbeReasonPeriodic || value == ProbeReasonEndpointChanged || value == ProbeReasonSessionMismatch
}

func validTrustSource(value TrustSource) bool {
	return value == TrustSourceManual || value == TrustSourceExpected || value == TrustSourceTOFU || value == TrustSourceMigration
}

func validEvidenceKind(value EvidenceKind) bool {
	return value == EvidenceSSHHostKey || value == EvidenceSSHHostCertificate || value == EvidenceTLSLeaf || value == EvidenceTLSIntermediate || value == EvidenceTLSPresentedRoot
}

func validFailureCategory(value FailureCategory) bool {
	switch value {
	case FailureNoCompatibleWorker, FailureDNSResolution, FailureConnectionRefused, FailureConnectionTimeout,
		FailureProtocolMismatch, FailureInsecureDowngrade, FailureUnsupportedIdentityAlgorithm,
		FailureMalformedIdentity, FailureIdentityTooLarge, FailureCertificateExpired,
		FailureCertificateNotYetValid, FailureNameMismatch, FailureExpectationMismatch,
		FailureWorkerLost, FailureLeaseExpired, FailureTargetIdentityChanged:
		return true
	default:
		return false
	}
}
