package targetidentity

import (
	"context"
	"errors"
	"fmt"
	"time"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	targetidentityv1 "github.com/trevex/jumpgate/warden/gen/jumpgate/targetidentity/v1"
	"github.com/trevex/jumpgate/warden/internal/apiguard"
	"github.com/trevex/jumpgate/warden/internal/apipage"
	"github.com/trevex/jumpgate/warden/internal/auth"
	"github.com/trevex/jumpgate/warden/internal/authz"
)

// Handler is the existence-hiding management transport for target identity.
type Handler struct {
	svc   *Service
	guard apiguard.Guard
}

// NewHandler constructs a TargetIdentityService transport adapter.
func NewHandler(svc *Service, guard apiguard.Guard) *Handler {
	return &Handler{svc: svc, guard: guard}
}

func (h *Handler) authorizeAsset(ctx context.Context, assetID uuid.UUID, capability string) (uuid.UUID, error) {
	caller, ok := auth.UserFromContext(ctx)
	if !ok {
		return uuid.Nil, connect.NewError(connect.CodeUnauthenticated, errors.New("authentication required"))
	}
	if _, err := h.guard.Q.GetAsset(ctx, assetID); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return uuid.Nil, connect.NewError(connect.CodeNotFound, errors.New("asset not found"))
		}
		return uuid.Nil, connect.NewError(connect.CodeInternal, err)
	}
	visible, err := authz.AssetVisible(ctx, h.guard.Authz, caller.ID, assetID)
	if err != nil {
		return uuid.Nil, connect.NewError(connect.CodeInternal, err)
	}
	caps, err := h.guard.Authz.CapabilitiesOnScope(ctx, caller.ID, authz.AssetScope(assetID))
	if err != nil {
		return uuid.Nil, connect.NewError(connect.CodeInternal, err)
	}
	visible = visible || caps.Allows(authz.AssetProbeCap) || caps.Allows(authz.AssetIdentityReadCap) || caps.Allows(authz.AssetIdentityApproveCap)
	if !visible {
		return uuid.Nil, connect.NewError(connect.CodeNotFound, errors.New("asset not found"))
	}
	if err := h.guard.RequireCap(ctx, caller.ID, capability, authz.AssetScope(assetID)); err != nil {
		return uuid.Nil, err
	}
	return caller.ID, nil
}

func parseAssetID(raw string) (uuid.UUID, error) {
	id, err := uuid.Parse(raw)
	if err != nil {
		return uuid.Nil, connect.NewError(connect.CodeInvalidArgument, errors.New("invalid asset_id"))
	}
	return id, nil
}

func parseUUID(raw, field string) (uuid.UUID, error) {
	id, err := uuid.Parse(raw)
	if err != nil {
		return uuid.Nil, connect.NewError(connect.CodeInvalidArgument, fmt.Errorf("invalid %s", field))
	}
	return id, nil
}

func domainError(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, ErrInvalidRequest), errors.Is(err, ErrInvalidResult):
		return connect.NewError(connect.CodeInvalidArgument, errors.New("invalid target identity request"))
	case errors.Is(err, ErrStaleRevision):
		return connect.NewError(connect.CodeAborted, errors.New("stale endpoint revision"))
	case errors.Is(err, ErrExpectationMismatch), errors.Is(err, ErrUnsupportedEvidence), errors.Is(err, ErrValidationFactNeeded), errors.Is(err, ErrProbeAlreadyQueued), errors.Is(err, ErrIdempotencyConflict):
		return connect.NewError(connect.CodeFailedPrecondition, err)
	case errors.Is(err, ErrAssetNotFound), errors.Is(err, ErrObservationNotFound), errors.Is(err, ErrEvidenceNotFound), errors.Is(err, ErrAnchorNotFound):
		return connect.NewError(connect.CodeNotFound, errors.New("target identity resource not found"))
	default:
		return connect.NewError(connect.CodeInternal, err)
	}
}

func unixMillis(value time.Time) int64 {
	if value.IsZero() {
		return 0
	}
	return value.UnixMilli()
}

func timeFromUnixMillis(value int64) time.Time {
	if value == 0 {
		return time.Time{}
	}
	return time.UnixMilli(value)
}

func probeMsg(job ProbeJob) *targetidentityv1.ProbeJob {
	return &targetidentityv1.ProbeJob{
		Id: job.ID.String(), PreviousProbeId: uuidString(job.PreviousJobID), AssetId: job.AssetID.String(), EndpointRevision: job.EndpointRevision,
		Protocol: protocolMsg(job.Protocol), State: probeStateMsg(job.State), Reason: probeReasonMsg(job.Reason),
		AttemptCount: boundedInt32(job.AttemptCount), MaxAttempts: boundedInt32(job.MaxAttempts), NextAttemptAtUnixMs: unixMillis(job.NextAttemptAt), CreatedAtUnixMs: unixMillis(job.CreatedAt),
		FailureCategory: failureCategoryMsg(job.FailureCategory), FailureDetail: job.FailureDetail, StartedAtUnixMs: unixMillis(job.StartedAt), CompletedAtUnixMs: unixMillis(job.CompletedAt),
	}
}

func evidenceMsg(item Evidence) *targetidentityv1.Evidence {
	out := &targetidentityv1.Evidence{
		Id: item.ID.String(), ObservationId: item.ObservationID.String(), Kind: evidenceKindMsg(item.Kind), Algorithm: item.Algorithm,
		Sha256Fingerprint: item.Fingerprint, PublicMaterial: item.PublicMaterial, CertificateSubject: item.CertificateSubject,
		CertificateIssuer: item.CertificateIssuer, IssuerSha256Fingerprint: item.IssuerFingerprint,
		DnsNames: cloneStrings(item.DNSNames), IpAddresses: cloneStrings(item.IPAddresses), SshPrincipals: cloneStrings(item.SSHPrincipals),
		SerialNumber: item.SerialNumber, ValidFromUnixMs: unixMillis(item.ValidFrom), ValidUntilUnixMs: unixMillis(item.ValidUntil),
		KeyBits: boundedInt32(item.Key.Bits), KeyCurve: item.Key.Curve, CreatedAtUnixMs: unixMillis(item.CreatedAt),
	}
	for _, extension := range item.DisplayExtensions {
		out.DisplayExtensions = append(out.DisplayExtensions, &targetidentityv1.DisplayExtension{Name: extension.Name, Value: extension.Value})
	}
	return out
}

func observationMsg(item Observation) *targetidentityv1.Observation {
	out := &targetidentityv1.Observation{
		Id: item.ID.String(), ProbeId: uuidString(item.JobID), AssetId: item.AssetID.String(), EndpointRevision: item.EndpointRevision,
		Source: observationSourceMsg(item.Source), ResolvedAddresses: cloneStrings(item.ResolvedAddresses), ObservedAtUnixMs: unixMillis(item.ObservedAt),
		Outcome: observationOutcomeMsg(item.Outcome), ValidationState: validationStateMsg(item.ValidationState), FailureCategory: failureCategoryMsg(item.FailureCategory),
		FailureDetail: item.FailureDetail,
	}
	for _, evidence := range item.Evidence {
		out.Evidence = append(out.Evidence, evidenceMsg(evidence))
	}
	switch {
	case item.SSH != nil:
		out.ProtocolMetadata = &targetidentityv1.Observation_Ssh{Ssh: &targetidentityv1.SSHMetadata{Banner: item.SSH.Banner, HostKeyAlgorithms: cloneStrings(item.SSH.HostKeyAlgorithms)}}
	case item.TLS != nil:
		out.ProtocolMetadata = &targetidentityv1.Observation_Tls{Tls: &targetidentityv1.TLSMetadata{Version: item.TLS.Version, CipherSuite: item.TLS.CipherSuite, ServerName: item.TLS.ServerName, Alpn: item.TLS.ALPN}}
	case item.Kubernetes != nil:
		out.ProtocolMetadata = &targetidentityv1.Observation_Kubernetes{Kubernetes: &targetidentityv1.KubernetesMetadata{ApiServerName: item.Kubernetes.APIServerName}}
	}
	return out
}

func anchorMsg(anchor TrustAnchor) *targetidentityv1.TrustAnchor {
	return &targetidentityv1.TrustAnchor{
		Id: anchor.ID.String(), AssetId: anchor.AssetID.String(), EndpointRevision: anchor.EndpointRevision, Kind: anchorKindMsg(anchor.Kind),
		Algorithm: anchor.Algorithm, Sha256Fingerprint: anchor.Fingerprint, PublicMaterial: anchor.PublicMaterial,
		RequiredSshPrincipals: cloneStrings(anchor.RequiredSSHPrincipals), RequiredDnsNames: cloneStrings(anchor.RequiredDNSNames), RequiredIpAddresses: cloneStrings(anchor.RequiredIPAddresses),
		Source: trustSourceMsg(anchor.Source), ObservationId: uuidString(anchor.ObservationID), ApprovedBy: uuidString(anchor.ApprovedBy), ApprovedAtUnixMs: unixMillis(anchor.ApprovedAt),
		NotBeforeUnixMs: unixMillis(anchor.NotBefore), ExpiresAtUnixMs: unixMillis(anchor.ExpiresAt), RevokedAtUnixMs: unixMillis(anchor.RevokedAt),
		RevokedBy: uuidString(anchor.RevokedBy), RevocationReason: anchor.RevocationReason,
	}
}

func uuidString(id uuid.UUID) string {
	if id == uuid.Nil {
		return ""
	}
	return id.String()
}

func boundedInt32(value int) int32 {
	const maxInt32 = int(^uint32(0) >> 1)
	if value < 0 {
		return 0
	}
	if value > maxInt32 {
		return int32(maxInt32) //nolint:gosec // explicitly bounded above
	}
	return int32(value) //nolint:gosec // explicitly bounded above and below
}

// StartProbe queues a manual credential-free probe for the current endpoint.
func (h *Handler) StartProbe(ctx context.Context, req *connect.Request[targetidentityv1.StartProbeRequest]) (*connect.Response[targetidentityv1.StartProbeResponse], error) {
	assetID, err := parseAssetID(req.Msg.GetAssetId())
	if err != nil {
		return nil, err
	}
	actorID, err := h.authorizeAsset(ctx, assetID, authz.AssetProbeCap)
	if err != nil {
		return nil, err
	}
	requestID, err := parseUUID(req.Msg.GetRequestId(), "request_id")
	if err != nil {
		return nil, err
	}
	previousID := uuid.Nil
	if req.Msg.GetPreviousProbeId() != "" {
		previousID, err = parseUUID(req.Msg.GetPreviousProbeId(), "previous_probe_id")
		if err != nil {
			return nil, err
		}
	}
	job, err := h.svc.QueueProbe(ctx, QueueProbeRequest{RequestID: requestID, AssetID: assetID, EndpointRevision: req.Msg.GetExpectedEndpointRevision(), Reason: ProbeReasonManual, RequestedBy: actorID, PreviousJobID: previousID})
	if err != nil {
		return nil, domainError(err)
	}
	return connect.NewResponse(&targetidentityv1.StartProbeResponse{Probe: probeMsg(job)}), nil
}

// GetProbe returns one probe job belonging to the authorized asset.
func (h *Handler) GetProbe(ctx context.Context, req *connect.Request[targetidentityv1.GetProbeRequest]) (*connect.Response[targetidentityv1.GetProbeResponse], error) {
	assetID, err := parseAssetID(req.Msg.GetAssetId())
	if err != nil {
		return nil, err
	}
	if _, err := h.authorizeAsset(ctx, assetID, authz.AssetIdentityReadCap); err != nil {
		return nil, err
	}
	probeID, err := parseUUID(req.Msg.GetProbeId(), "probe_id")
	if err != nil {
		return nil, err
	}
	job, err := h.svc.GetProbe(ctx, assetID, probeID)
	if err != nil {
		return nil, domainError(err)
	}
	return connect.NewResponse(&targetidentityv1.GetProbeResponse{Probe: probeMsg(job)}), nil
}

// ListProbes returns a bounded page of probe history for an asset.
func (h *Handler) ListProbes(ctx context.Context, req *connect.Request[targetidentityv1.ListProbesRequest]) (*connect.Response[targetidentityv1.ListProbesResponse], error) {
	assetID, err := parseAssetID(req.Msg.GetAssetId())
	if err != nil {
		return nil, err
	}
	if _, err := h.authorizeAsset(ctx, assetID, authz.AssetIdentityReadCap); err != nil {
		return nil, err
	}
	page, err := pageRequest(req.Msg.GetPageSize(), req.Msg.GetPageToken())
	if err != nil {
		return nil, err
	}
	rows, hasMore, err := h.svc.ListProbesPage(ctx, assetID, page)
	if err != nil {
		return nil, domainError(err)
	}
	out := &targetidentityv1.ListProbesResponse{}
	for _, row := range rows {
		out.Probes = append(out.Probes, probeMsg(row))
	}
	if hasMore {
		last := rows[len(rows)-1]
		out.NextPageToken = apipage.EncodeTimeToken(last.CreatedAt, last.ID)
	}
	return connect.NewResponse(out), nil
}

// ListObservations returns a bounded page of immutable public evidence.
func (h *Handler) ListObservations(ctx context.Context, req *connect.Request[targetidentityv1.ListObservationsRequest]) (*connect.Response[targetidentityv1.ListObservationsResponse], error) {
	assetID, err := parseAssetID(req.Msg.GetAssetId())
	if err != nil {
		return nil, err
	}
	if _, err := h.authorizeAsset(ctx, assetID, authz.AssetIdentityReadCap); err != nil {
		return nil, err
	}
	page, err := pageRequest(req.Msg.GetPageSize(), req.Msg.GetPageToken())
	if err != nil {
		return nil, err
	}
	rows, hasMore, err := h.svc.ListObservationsPage(ctx, assetID, page)
	if err != nil {
		return nil, domainError(err)
	}
	out := &targetidentityv1.ListObservationsResponse{}
	for _, row := range rows {
		out.Observations = append(out.Observations, observationMsg(row))
	}
	if hasMore {
		last := rows[len(rows)-1]
		out.NextPageToken = apipage.EncodeTimeToken(last.ObservedAt, last.ID)
	}
	return connect.NewResponse(out), nil
}

// ApproveEvidence approves one or more exact observed identity items.
func (h *Handler) ApproveEvidence(ctx context.Context, req *connect.Request[targetidentityv1.ApproveEvidenceRequest]) (*connect.Response[targetidentityv1.ApproveEvidenceResponse], error) {
	assetID, err := parseAssetID(req.Msg.GetAssetId())
	if err != nil {
		return nil, err
	}
	actorID, err := h.authorizeAsset(ctx, assetID, authz.AssetIdentityApproveCap)
	if err != nil {
		return nil, err
	}
	observationID, err := parseUUID(req.Msg.GetObservationId(), "observation_id")
	if err != nil {
		return nil, err
	}
	requestID, err := parseUUID(req.Msg.GetRequestId(), "request_id")
	if err != nil {
		return nil, err
	}
	evidenceIDs := make([]uuid.UUID, 0, len(req.Msg.GetEvidenceIds()))
	for _, rawID := range req.Msg.GetEvidenceIds() {
		id, err := parseUUID(rawID, "evidence_id")
		if err != nil {
			return nil, err
		}
		evidenceIDs = append(evidenceIDs, id)
	}
	anchors, status, err := h.svc.ApproveEvidenceBatch(ctx, ApproveEvidenceBatchRequest{
		RequestID: requestID, AssetID: assetID, ExpectedRevision: req.Msg.GetExpectedEndpointRevision(), ObservationID: observationID,
		EvidenceIDs: evidenceIDs, Source: trustSource(req.Msg.GetSource()), ActorID: actorID,
		NotBefore: timeFromUnixMillis(req.Msg.GetNotBeforeUnixMs()), ExpiresAt: timeFromUnixMillis(req.Msg.GetExpiresAtUnixMs()),
	})
	if err != nil {
		return nil, domainError(err)
	}
	out := &targetidentityv1.ApproveEvidenceResponse{Status: verificationStatusMsg(status)}
	for _, anchor := range anchors {
		out.TrustAnchors = append(out.TrustAnchors, anchorMsg(anchor))
	}
	return connect.NewResponse(out), nil
}

// ApproveCA approves operator-supplied CA material bound to observed validation.
func (h *Handler) ApproveCA(ctx context.Context, req *connect.Request[targetidentityv1.ApproveCARequest]) (*connect.Response[targetidentityv1.ApproveCAResponse], error) {
	assetID, err := parseAssetID(req.Msg.GetAssetId())
	if err != nil {
		return nil, err
	}
	actorID, err := h.authorizeAsset(ctx, assetID, authz.AssetIdentityApproveCap)
	if err != nil {
		return nil, err
	}
	observationID, err := parseUUID(req.Msg.GetObservationId(), "observation_id")
	if err != nil {
		return nil, err
	}
	validatedEvidenceID, err := parseUUID(req.Msg.GetValidatedEvidenceId(), "validated_evidence_id")
	if err != nil {
		return nil, err
	}
	requestID, err := parseUUID(req.Msg.GetRequestId(), "request_id")
	if err != nil {
		return nil, err
	}
	anchor, status, err := h.svc.Approve(ctx, ApproveRequest{
		RequestID: requestID, AssetID: assetID, ExpectedRevision: req.Msg.GetExpectedEndpointRevision(), ObservationID: observationID,
		AnchorKind: anchorKind(req.Msg.GetKind()), SuppliedAlgorithm: req.Msg.GetAlgorithm(), SuppliedPublicMaterial: req.Msg.GetPublicMaterial(),
		Source: trustSource(req.Msg.GetSource()), ActorID: actorID, RequiredSSHPrincipals: req.Msg.GetRequiredSshPrincipals(),
		RequiredDNSNames: req.Msg.GetRequiredDnsNames(), RequiredIPAddresses: req.Msg.GetRequiredIpAddresses(), ValidatedEvidenceID: validatedEvidenceID,
		NotBefore: timeFromUnixMillis(req.Msg.GetNotBeforeUnixMs()), ExpiresAt: timeFromUnixMillis(req.Msg.GetExpiresAtUnixMs()),
	})
	if err != nil {
		return nil, domainError(err)
	}
	return connect.NewResponse(&targetidentityv1.ApproveCAResponse{TrustAnchor: anchorMsg(anchor), Status: verificationStatusMsg(status)}), nil
}

// RejectObservation explicitly resolves one current-revision mismatch.
func (h *Handler) RejectObservation(ctx context.Context, req *connect.Request[targetidentityv1.RejectObservationRequest]) (*connect.Response[targetidentityv1.RejectObservationResponse], error) {
	assetID, err := parseAssetID(req.Msg.GetAssetId())
	if err != nil {
		return nil, err
	}
	actorID, err := h.authorizeAsset(ctx, assetID, authz.AssetIdentityApproveCap)
	if err != nil {
		return nil, err
	}
	observationID, err := parseUUID(req.Msg.GetObservationId(), "observation_id")
	if err != nil {
		return nil, err
	}
	requestID, err := parseUUID(req.Msg.GetRequestId(), "request_id")
	if err != nil {
		return nil, err
	}
	status, err := h.svc.RejectObservation(ctx, RejectObservationRequest{RequestID: requestID, AssetID: assetID, ExpectedRevision: req.Msg.GetExpectedEndpointRevision(), ObservationID: observationID, ActorID: actorID, Reason: req.Msg.GetReason()})
	if err != nil {
		return nil, domainError(err)
	}
	return connect.NewResponse(&targetidentityv1.RejectObservationResponse{Status: verificationStatusMsg(status)}), nil
}

// ListTrustAnchors returns a bounded page of complete trust-anchor history.
func (h *Handler) ListTrustAnchors(ctx context.Context, req *connect.Request[targetidentityv1.ListTrustAnchorsRequest]) (*connect.Response[targetidentityv1.ListTrustAnchorsResponse], error) {
	assetID, err := parseAssetID(req.Msg.GetAssetId())
	if err != nil {
		return nil, err
	}
	if _, err := h.authorizeAsset(ctx, assetID, authz.AssetIdentityReadCap); err != nil {
		return nil, err
	}
	page, err := pageRequest(req.Msg.GetPageSize(), req.Msg.GetPageToken())
	if err != nil {
		return nil, err
	}
	rows, hasMore, err := h.svc.ListAnchorsPage(ctx, assetID, page)
	if err != nil {
		return nil, domainError(err)
	}
	out := &targetidentityv1.ListTrustAnchorsResponse{}
	for _, row := range rows {
		out.TrustAnchors = append(out.TrustAnchors, anchorMsg(row))
	}
	if hasMore {
		last := rows[len(rows)-1]
		out.NextPageToken = apipage.EncodeTimeToken(last.ApprovedAt, last.ID)
	}
	return connect.NewResponse(out), nil
}

// RevokeTrustAnchor explicitly ends trust in one additive anchor.
func (h *Handler) RevokeTrustAnchor(ctx context.Context, req *connect.Request[targetidentityv1.RevokeTrustAnchorRequest]) (*connect.Response[targetidentityv1.RevokeTrustAnchorResponse], error) {
	assetID, err := parseAssetID(req.Msg.GetAssetId())
	if err != nil {
		return nil, err
	}
	actorID, err := h.authorizeAsset(ctx, assetID, authz.AssetIdentityApproveCap)
	if err != nil {
		return nil, err
	}
	anchorID, err := parseUUID(req.Msg.GetTrustAnchorId(), "trust_anchor_id")
	if err != nil {
		return nil, err
	}
	requestID, err := parseUUID(req.Msg.GetRequestId(), "request_id")
	if err != nil {
		return nil, err
	}
	status, err := h.svc.RevokeAnchor(ctx, RevokeAnchorRequest{RequestID: requestID, AssetID: assetID, ExpectedRevision: req.Msg.GetExpectedEndpointRevision(), AnchorID: anchorID, ActorID: actorID, Reason: req.Msg.GetReason()})
	if err != nil {
		return nil, domainError(err)
	}
	return connect.NewResponse(&targetidentityv1.RevokeTrustAnchorResponse{Status: verificationStatusMsg(status)}), nil
}

// GetVerificationStatus derives the current user-facing verification state.
func (h *Handler) GetVerificationStatus(ctx context.Context, req *connect.Request[targetidentityv1.GetVerificationStatusRequest]) (*connect.Response[targetidentityv1.GetVerificationStatusResponse], error) {
	assetID, err := parseAssetID(req.Msg.GetAssetId())
	if err != nil {
		return nil, err
	}
	if _, err := h.authorizeAsset(ctx, assetID, authz.AssetIdentityReadCap); err != nil {
		return nil, err
	}
	status, err := h.svc.Status(ctx, StatusRequest{AssetID: assetID, Freshness: time.Duration(req.Msg.GetFreshnessSeconds()) * time.Second})
	if err != nil {
		return nil, domainError(err)
	}
	return connect.NewResponse(&targetidentityv1.GetVerificationStatusResponse{Status: verificationStatusMsg(status)}), nil
}

func pageRequest(pageSize int32, token string) (PageRequest, error) {
	decoded, err := apipage.DecodePageToken(token)
	if err != nil {
		return PageRequest{}, err
	}
	page := PageRequest{Limit: int(apipage.ClampPageSize(pageSize))}
	if decoded != nil {
		if decoded.Time == nil || decoded.Name != "" {
			return PageRequest{}, connect.NewError(connect.CodeInvalidArgument, errors.New("bad page_token"))
		}
		page.AfterTime = *decoded.Time
		page.AfterID = decoded.ID
	}
	return page, nil
}

func protocolMsg(v Protocol) targetidentityv1.Protocol {
	return map[Protocol]targetidentityv1.Protocol{ProtocolSSH: targetidentityv1.Protocol_PROTOCOL_SSH, ProtocolPostgres: targetidentityv1.Protocol_PROTOCOL_POSTGRES, ProtocolRDP: targetidentityv1.Protocol_PROTOCOL_RDP, ProtocolKubernetes: targetidentityv1.Protocol_PROTOCOL_KUBERNETES}[v]
}
func probeStateMsg(v ProbeState) targetidentityv1.ProbeState {
	return map[ProbeState]targetidentityv1.ProbeState{ProbeQueued: targetidentityv1.ProbeState_PROBE_STATE_QUEUED, ProbeLeased: targetidentityv1.ProbeState_PROBE_STATE_LEASED, ProbeStateSucceeded: targetidentityv1.ProbeState_PROBE_STATE_SUCCEEDED, ProbeStateFailed: targetidentityv1.ProbeState_PROBE_STATE_FAILED, ProbeSuperseded: targetidentityv1.ProbeState_PROBE_STATE_SUPERSEDED, ProbeCancelled: targetidentityv1.ProbeState_PROBE_STATE_CANCELLED}[v]
}
func probeReasonMsg(v ProbeReason) targetidentityv1.ProbeReason {
	return map[ProbeReason]targetidentityv1.ProbeReason{ProbeReasonOnboarding: targetidentityv1.ProbeReason_PROBE_REASON_ONBOARDING, ProbeReasonManual: targetidentityv1.ProbeReason_PROBE_REASON_MANUAL, ProbeReasonPeriodic: targetidentityv1.ProbeReason_PROBE_REASON_PERIODIC, ProbeReasonEndpointChanged: targetidentityv1.ProbeReason_PROBE_REASON_ENDPOINT_CHANGED, ProbeReasonSessionMismatch: targetidentityv1.ProbeReason_PROBE_REASON_SESSION_MISMATCH}[v]
}
func observationSourceMsg(v ObservationSource) targetidentityv1.ObservationSource {
	return map[ObservationSource]targetidentityv1.ObservationSource{ObservationProbe: targetidentityv1.ObservationSource_OBSERVATION_SOURCE_PROBE, ObservationSessionMismatch: targetidentityv1.ObservationSource_OBSERVATION_SOURCE_SESSION_MISMATCH}[v]
}
func evidenceKindMsg(v EvidenceKind) targetidentityv1.EvidenceKind {
	return map[EvidenceKind]targetidentityv1.EvidenceKind{EvidenceSSHHostKey: targetidentityv1.EvidenceKind_EVIDENCE_KIND_SSH_HOST_KEY, EvidenceSSHHostCertificate: targetidentityv1.EvidenceKind_EVIDENCE_KIND_SSH_HOST_CERTIFICATE, EvidenceTLSLeaf: targetidentityv1.EvidenceKind_EVIDENCE_KIND_TLS_LEAF, EvidenceTLSIntermediate: targetidentityv1.EvidenceKind_EVIDENCE_KIND_TLS_INTERMEDIATE, EvidenceTLSPresentedRoot: targetidentityv1.EvidenceKind_EVIDENCE_KIND_TLS_PRESENTED_ROOT}[v]
}
func anchorKindMsg(v TrustAnchorKind) targetidentityv1.TrustAnchorKind {
	return map[TrustAnchorKind]targetidentityv1.TrustAnchorKind{AnchorSSHHostKey: targetidentityv1.TrustAnchorKind_TRUST_ANCHOR_KIND_SSH_HOST_KEY, AnchorSSHHostCA: targetidentityv1.TrustAnchorKind_TRUST_ANCHOR_KIND_SSH_HOST_CA, AnchorTLSCA: targetidentityv1.TrustAnchorKind_TRUST_ANCHOR_KIND_TLS_CA, AnchorTLSLeaf: targetidentityv1.TrustAnchorKind_TRUST_ANCHOR_KIND_TLS_LEAF}[v]
}
func trustSourceMsg(v TrustSource) targetidentityv1.TrustSource {
	return map[TrustSource]targetidentityv1.TrustSource{TrustSourceManual: targetidentityv1.TrustSource_TRUST_SOURCE_MANUAL, TrustSourceExpected: targetidentityv1.TrustSource_TRUST_SOURCE_EXPECTED, TrustSourceTOFU: targetidentityv1.TrustSource_TRUST_SOURCE_TOFU, TrustSourceMigration: targetidentityv1.TrustSource_TRUST_SOURCE_MIGRATION}[v]
}
func trustSource(v targetidentityv1.TrustSource) TrustSource {
	return map[targetidentityv1.TrustSource]TrustSource{targetidentityv1.TrustSource_TRUST_SOURCE_MANUAL: TrustSourceManual, targetidentityv1.TrustSource_TRUST_SOURCE_EXPECTED: TrustSourceExpected, targetidentityv1.TrustSource_TRUST_SOURCE_TOFU: TrustSourceTOFU, targetidentityv1.TrustSource_TRUST_SOURCE_MIGRATION: TrustSourceMigration}[v]
}
func anchorKind(v targetidentityv1.TrustAnchorKind) TrustAnchorKind {
	return map[targetidentityv1.TrustAnchorKind]TrustAnchorKind{targetidentityv1.TrustAnchorKind_TRUST_ANCHOR_KIND_SSH_HOST_KEY: AnchorSSHHostKey, targetidentityv1.TrustAnchorKind_TRUST_ANCHOR_KIND_SSH_HOST_CA: AnchorSSHHostCA, targetidentityv1.TrustAnchorKind_TRUST_ANCHOR_KIND_TLS_CA: AnchorTLSCA, targetidentityv1.TrustAnchorKind_TRUST_ANCHOR_KIND_TLS_LEAF: AnchorTLSLeaf}[v]
}
func verificationStatusMsg(v VerificationStatus) targetidentityv1.VerificationStatus {
	return map[VerificationStatus]targetidentityv1.VerificationStatus{StatusPendingVerification: targetidentityv1.VerificationStatus_VERIFICATION_STATUS_PENDING_VERIFICATION, StatusProbeFailed: targetidentityv1.VerificationStatus_VERIFICATION_STATUS_PROBE_FAILED, StatusAwaitingApproval: targetidentityv1.VerificationStatus_VERIFICATION_STATUS_AWAITING_APPROVAL, StatusVerified: targetidentityv1.VerificationStatus_VERIFICATION_STATUS_VERIFIED, StatusIdentityChanged: targetidentityv1.VerificationStatus_VERIFICATION_STATUS_IDENTITY_CHANGED, StatusVerificationExpired: targetidentityv1.VerificationStatus_VERIFICATION_STATUS_VERIFICATION_EXPIRED}[v]
}
func observationOutcomeMsg(v string) targetidentityv1.ObservationOutcome {
	return map[string]targetidentityv1.ObservationOutcome{"succeeded": targetidentityv1.ObservationOutcome_OBSERVATION_OUTCOME_SUCCEEDED, "failed": targetidentityv1.ObservationOutcome_OBSERVATION_OUTCOME_FAILED, "mismatch": targetidentityv1.ObservationOutcome_OBSERVATION_OUTCOME_MISMATCH, "stale": targetidentityv1.ObservationOutcome_OBSERVATION_OUTCOME_STALE}[v]
}
func validationStateMsg(v string) targetidentityv1.ValidationState {
	return map[string]targetidentityv1.ValidationState{"unvalidated": targetidentityv1.ValidationState_VALIDATION_STATE_UNVALIDATED, "validated": targetidentityv1.ValidationState_VALIDATION_STATE_VALIDATED, "failed": targetidentityv1.ValidationState_VALIDATION_STATE_FAILED}[v]
}
func failureCategoryMsg(v FailureCategory) targetidentityv1.FailureCategory {
	return map[FailureCategory]targetidentityv1.FailureCategory{FailureNoCompatibleWorker: targetidentityv1.FailureCategory_FAILURE_CATEGORY_NO_COMPATIBLE_WORKER, FailureDNSResolution: targetidentityv1.FailureCategory_FAILURE_CATEGORY_DNS_RESOLUTION_FAILED, FailureConnectionRefused: targetidentityv1.FailureCategory_FAILURE_CATEGORY_CONNECTION_REFUSED, FailureConnectionTimeout: targetidentityv1.FailureCategory_FAILURE_CATEGORY_CONNECTION_TIMEOUT, FailureProtocolMismatch: targetidentityv1.FailureCategory_FAILURE_CATEGORY_PROTOCOL_MISMATCH, FailureInsecureDowngrade: targetidentityv1.FailureCategory_FAILURE_CATEGORY_INSECURE_DOWNGRADE, FailureUnsupportedIdentityAlgorithm: targetidentityv1.FailureCategory_FAILURE_CATEGORY_UNSUPPORTED_IDENTITY_ALGORITHM, FailureMalformedIdentity: targetidentityv1.FailureCategory_FAILURE_CATEGORY_MALFORMED_IDENTITY, FailureIdentityTooLarge: targetidentityv1.FailureCategory_FAILURE_CATEGORY_IDENTITY_TOO_LARGE, FailureCertificateExpired: targetidentityv1.FailureCategory_FAILURE_CATEGORY_CERTIFICATE_EXPIRED, FailureCertificateNotYetValid: targetidentityv1.FailureCategory_FAILURE_CATEGORY_CERTIFICATE_NOT_YET_VALID, FailureNameMismatch: targetidentityv1.FailureCategory_FAILURE_CATEGORY_NAME_MISMATCH, FailureExpectationMismatch: targetidentityv1.FailureCategory_FAILURE_CATEGORY_EXPECTATION_MISMATCH, FailureWorkerLost: targetidentityv1.FailureCategory_FAILURE_CATEGORY_WORKER_LOST, FailureLeaseExpired: targetidentityv1.FailureCategory_FAILURE_CATEGORY_LEASE_EXPIRED, FailureTargetIdentityChanged: targetidentityv1.FailureCategory_FAILURE_CATEGORY_TARGET_IDENTITY_CHANGED}[v]
}
