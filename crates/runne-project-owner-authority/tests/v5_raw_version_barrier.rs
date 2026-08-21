use runne_project_owner_authority::{
    AuthorityError, verify_destination_allowlist_v1_bytes, verify_evidence_envelope_v2_bytes,
    verify_promotion_authority_receipt_v5_bytes, verify_stage_envelope_v2_bytes,
};

#[test]
fn raw_v5_front_doors_reject_legacy_versions_before_finalized_pin_validation() {
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
fn raw_v5_front_doors_accept_their_exact_version_with_finalized_pins() {
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
        assert_eq!(verify(bytes.as_bytes()), Ok(()));
    }
}

#[test]
fn raw_v5_front_doors_do_not_accept_same_version_runne_aliases() {
    for (schema, verify) in [
        (
            "runne.project-owner.authority-receipt/5",
            verify_promotion_authority_receipt_v5_bytes as fn(&[u8]) -> _,
        ),
        (
            "runne.release.post-rc0-stage-envelope/2",
            verify_stage_envelope_v2_bytes,
        ),
        (
            "runne.release.post-rc0-evidence-envelope/2",
            verify_evidence_envelope_v2_bytes,
        ),
        (
            "runne.project-owner.publication-destination-allowlist/1",
            verify_destination_allowlist_v1_bytes,
        ),
    ] {
        let bytes = format!(r#"{{"schema_version":"{schema}"}}"#) + "\n";
        assert!(verify(bytes.as_bytes()).is_err(), "{schema}");
    }
}

#[test]
fn raw_v5_front_doors_reject_noncanonical_wire_with_finalized_pins() {
    let schema = "gocode.project-owner.authority-receipt/5";
    let canonical = format!(r#"{{"schema_version":"{schema}"}}"#) + "\n";
    assert_eq!(
        verify_promotion_authority_receipt_v5_bytes(canonical.as_bytes()),
        Ok(())
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
fn raw_v5_front_doors_reject_unknown_fields_before_finalized_pin_validation() {
    let bytes =
        b"{\"schema_version\":\"gocode.release.post-rc0-stage-envelope/2\",\"unexpected\":true}\n";
    assert_eq!(
        verify_stage_envelope_v2_bytes(bytes),
        Err(AuthorityError::UnknownField("unexpected".into()))
    );
}
