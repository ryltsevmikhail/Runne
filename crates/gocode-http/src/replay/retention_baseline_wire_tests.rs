use gocode_application::prohibited_content::ContentGuardError;

struct BaselineResponseAllowed;
struct RawMarkerGuard;

impl ProhibitedContentPort for BaselineResponseAllowed {
    fn inspect(
        &self,
        _: CanonicalContentBoundary,
        _: &[u8],
    ) -> Result<ContentDisposition, ContentGuardError> {
        Ok(ContentDisposition::Allowed { policy_epoch: 1 })
    }
}

impl ProhibitedContentPort for RawMarkerGuard {
    fn inspect(
        &self,
        _: CanonicalContentBoundary,
        bytes: &[u8],
    ) -> Result<ContentDisposition, ContentGuardError> {
        Ok(if bytes.windows(6).any(|value| value == b"marker") {
            ContentDisposition::Prohibited { policy_epoch: 2 }
        } else {
            ContentDisposition::Allowed { policy_epoch: 2 }
        })
    }
}

#[test]
fn oversized_retention_baseline_response_is_rejected_before_http_response_creation() {
    let baseline = gocode_api::ReplayRetentionBaselineWireV1::from_unauthenticated_fields(
        gocode_api::UnauthenticatedReplayRetentionBaselineFieldsV1 {
            schema_version: 1,
            authority_id: [1; 16],
            principal_id: "x".repeat(MAX_RETENTION_BASELINE_RESPONSE_BYTES),
            lineage_id: [2; 16],
            runtime_session_binding_digest: [3; 32],
            replay_scope_digest: [4; 32],
            aggregate_kind: gocode_api::ApiReplayAggregateKind::TaskRun,
            aggregate_id: [5; 16],
            sequence: 1,
            version: 1,
            baseline_global_position: 1,
            projection_codec: 1,
            projection_bytes: vec![6],
            projection_digest: [7; 32],
            retained_floor: 1,
            captured_high_water: 1,
            retention_generation: 1,
            retention_witness: [8; 32],
            issued_at_unix_ms: 1,
            expires_at_unix_ms: 2,
            witness_mac: [9; 32],
        },
    );

    let error =
        retention_baseline_response(&baseline, &RequestId::generate(), &BaselineResponseAllowed)
            .unwrap_err();

    assert_eq!(error.code, "replay_backpressure");
}

#[test]
fn raw_projection_marker_is_denied_before_base64_wire_encoding() {
    let baseline = gocode_api::ReplayRetentionBaselineWireV1::from_unauthenticated_fields(
        gocode_api::UnauthenticatedReplayRetentionBaselineFieldsV1 {
            schema_version: 1, authority_id: [1; 16], principal_id: "owner".into(), lineage_id: [2; 16],
            runtime_session_binding_digest: [3; 32], replay_scope_digest: [4; 32],
            aggregate_kind: gocode_api::ApiReplayAggregateKind::Conversation, aggregate_id: [5; 16],
            sequence: 1, version: 1, baseline_global_position: 1, projection_codec: 1,
            projection_bytes: b"xxmarker".to_vec(), projection_digest: [7; 32], retained_floor: 2,
            captured_high_water: 2, retention_generation: 1, retention_witness: [8; 32],
            issued_at_unix_ms: 1, expires_at_unix_ms: 2, witness_mac: [9; 32],
        },
    );
    let error = retention_baseline_response(&baseline, &RequestId::generate(), &RawMarkerGuard)
        .unwrap_err();
    assert_eq!(error.code, "replay_sensitivity_denied");
}
