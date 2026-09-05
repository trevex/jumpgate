package targetidentity

import (
	"encoding/json"
	"sort"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/trevex/jumpgate/warden/internal/postgres/sqlc"
)

func nullableUUID(value uuid.UUID) pgtype.UUID {
	return pgtype.UUID{Bytes: value, Valid: value != uuid.Nil}
}

func nullableText(value string) pgtype.Text {
	return pgtype.Text{String: value, Valid: value != ""}
}

func nullableTime(value time.Time) pgtype.Timestamptz {
	return pgtype.Timestamptz{Time: value, Valid: !value.IsZero()}
}

func cloneStrings(values []string) []string {
	if len(values) == 0 {
		return []string{}
	}
	return append([]string(nil), values...)
}

func probeJobFromRow(row sqlc.TargetProbeJob) ProbeJob {
	return ProbeJob{ID: row.ID, PreviousJobID: uuidFromPG(row.PreviousJobID), AssetID: row.AssetID,
		EndpointRevision: row.EndpointRevision, Protocol: Protocol(row.Protocol), State: ProbeState(row.State),
		Reason: ProbeReason(row.Reason), AttemptCount: int(row.AttemptCount), MaxAttempts: int(row.MaxAttempts),
		NextAttemptAt: row.NextAttemptAt, CreatedAt: row.CreatedAt, StartedAt: timeFromPG(row.StartedAt), CompletedAt: timeFromPG(row.CompletedAt),
		FailureCategory: FailureCategory(textFromPG(row.FailureCategory)), FailureDetail: textFromPG(row.FailureDetail)}
}

func evidenceFromRow(row sqlc.TargetIdentityEvidence) Evidence {
	var key KeyMetadata
	var extensionMap map[string]string
	_ = json.Unmarshal(row.KeyMetadata, &key)
	_ = json.Unmarshal(row.DisplayExtensions, &extensionMap)
	extensionNames := make([]string, 0, len(extensionMap))
	for name := range extensionMap {
		extensionNames = append(extensionNames, name)
	}
	sort.Strings(extensionNames)
	extensions := make([]DisplayExtension, 0, len(extensionNames))
	for _, name := range extensionNames {
		extensions = append(extensions, DisplayExtension{Name: name, Value: extensionMap[name]})
	}
	return Evidence{ID: row.ID, ObservationID: row.ObservationID, Kind: EvidenceKind(row.Kind), Algorithm: row.Algorithm,
		Fingerprint: row.Sha256Fingerprint, PublicMaterial: row.PublicMaterial,
		CertificateSubject: textFromPG(row.CertificateSubject), CertificateIssuer: textFromPG(row.CertificateIssuer),
		IssuerFingerprint: textFromPG(row.IssuerSha256Fingerprint), DNSNames: cloneStrings(row.DnsNames),
		IPAddresses: cloneStrings(row.IpAddresses), SSHPrincipals: cloneStrings(row.SshPrincipals), SerialNumber: textFromPG(row.SerialNumber),
		ValidFrom: timeFromPG(row.ValidFrom), ValidUntil: timeFromPG(row.ValidUntil), Key: key, DisplayExtensions: extensions, CreatedAt: row.CreatedAt}
}

func trustAnchorFromRow(row sqlc.TargetTrustAnchor) TrustAnchor {
	return TrustAnchor{ID: row.ID, AssetID: row.AssetID, EndpointRevision: row.EndpointRevision, Kind: TrustAnchorKind(row.Kind),
		Algorithm: row.Algorithm, Fingerprint: row.Sha256Fingerprint, PublicMaterial: row.PublicMaterial,
		RequiredSSHPrincipals: cloneStrings(row.RequiredSshPrincipals), RequiredDNSNames: cloneStrings(row.RequiredDnsNames), RequiredIPAddresses: cloneStrings(row.RequiredIpAddresses),
		Source: TrustSource(row.Source), ObservationID: uuidFromPG(row.ObservationID), ApprovedBy: uuidFromPG(row.ApprovedBy), ApprovedAt: row.ApprovedAt,
		NotBefore: timeFromPG(row.NotBefore), ExpiresAt: timeFromPG(row.ExpiresAt), RevokedAt: timeFromPG(row.RevokedAt), RevokedBy: uuidFromPG(row.RevokedBy), RevocationReason: textFromPG(row.RevocationReason)}
}

func uuidFromPG(value pgtype.UUID) uuid.UUID {
	if !value.Valid {
		return uuid.Nil
	}
	return uuid.UUID(value.Bytes)
}

func textFromPG(value pgtype.Text) string {
	if !value.Valid {
		return ""
	}
	return value.String
}

func timeFromPG(value pgtype.Timestamptz) time.Time {
	if !value.Valid {
		return time.Time{}
	}
	return value.Time
}
