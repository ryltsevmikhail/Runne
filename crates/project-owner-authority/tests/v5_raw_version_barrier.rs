use gocode_project_owner_authority::{
    AuthorityError, verify_destination_allowlist_v1_bytes, verify_evidence_envelope_v2_bytes,
    verify_promotion_authority_receipt_v5_bytes, verify_stage_envelope_v2_bytes,
};

#[test]
fn raw_v5_front_doors_reject_legacy_versions_before_the_pending_pin_barrier() {
    for verify in [
        verify_promotion_authority_receipt_v5_bytes as fn(&[u8]) -> _,
        verify_stage_envelope_v2_bytes,
        verify_evidence_envelope_v2_bytes,
        verify_destination_allowlist_v1_bytes,
    ] {
        assert_eq!(
            verify(br#"{"schema_version":"gocode.release.post-rc0-stage-envelope/1"}"#),
            Err(AuthorityError::AuthorityVersionSuperseded)
        );
    }
}

#[test]
fn raw_v5_front_doors_reach_the_fail_closed_pin_barrier_for_their_exact_version() {
    for (schema, verify) in [
        (
            "gocode.project-owner.authority-receipt/5",
            verify_promotion_authority_receipt_v5_bytes as fn(&[u8]) -> _,
        ),
        (
            "gocode.release.post-rc0-stage-envelope/2",
            verify_stage_envelope_v2_bytes,
        ),
        (
            "gocode.release.post-rc0-evidence-envelope/2",
            verify_evidence_envelope_v2_bytes,
        ),
        (
            "gocode.project-owner.publication-destination-allowlist/1",
            verify_destination_allowlist_v1_bytes,
        ),
    ] {
        let bytes = format!(r#"{{"schema_version":"{schema}"}}"#) + "\n";
        assert_eq!(
            verify(bytes.as_bytes()),
            Err(AuthorityError::TrustV4PinsNotFinalized)
        );
    }
}

#[test]
fn raw_v5_front_doors_reject_noncanonical_wire_before_the_pin_barrier() {
    let schema = "gocode.project-owner.authority-receipt/5";
    let canonical = format!(r#"{{"schema_version":"{schema}"}}"#) + "\n";
    assert_eq!(
        verify_promotion_authority_receipt_v5_bytes(canonical.as_bytes()),
        Err(AuthorityError::TrustV4PinsNotFinalized)
    );
    assert_eq!(
        verify_promotion_authority_receipt_v5_bytes(canonical.trim_end().as_bytes()),
        Err(AuthorityError::InvalidCanonicalReceipt)
    );
    assert_eq!(
        verify_promotion_authority_receipt_v5_bytes(canonical.replace('\n', "\r\n").as_bytes()),
        Err(AuthorityError::InvalidCanonicalReceipt)
    );
}

#[test]
fn raw_v5_front_doors_reject_unknown_fields_before_the_pin_barrier() {
    let bytes =
        b"{\"schema_version\":\"gocode.release.post-rc0-stage-envelope/2\",\"unexpected\":true}\n";
    assert_eq!(
        verify_stage_envelope_v2_bytes(bytes),
        Err(AuthorityError::UnknownField("unexpected".into()))
    );
}
