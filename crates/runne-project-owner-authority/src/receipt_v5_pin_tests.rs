//! Verified pin-union and payload-schema ID tests against checked-in schema files.

use sha2::{Digest, Sha256};

#[test]
fn payload_schema_ids_match_checked_in_schema_dollar_ids() {
    let cases = [
        (
            "RC1_QUALIFICATION_AUTHORIZER",
            "transition",
            "gocode.release.rc1-qualification-decision/1",
            include_str!("../../../docs/schemas/release-rc1-qualification-decision-v1.schema.json"),
        ),
        (
            "RC2_SIGNING_AUTHORIZER",
            "transition",
            "gocode.release.rc2-signing-authorization/1",
            include_str!("../../../docs/schemas/rc2-signing-authorization-v1.schema.json"),
        ),
        (
            "RC3_PUBLICATION_AUTHORIZER",
            "transition",
            "gocode.release.rc3-publication-authorization/2",
            include_str!("../../../docs/schemas/rc3-publication-authorization-v2.schema.json"),
        ),
        (
            "RC2_NATIVE_EVIDENCE",
            "linux",
            "gocode.release.rc2-native-evidence/1",
            include_str!("../../../docs/schemas/rc2-native-evidence-v1.schema.json"),
        ),
        (
            "RC2_SIGNING_REVIEWER",
            "signing-review",
            "gocode.release.rc2-signing-review/1",
            include_str!("../../../docs/schemas/rc2-signing-review-v1.schema.json"),
        ),
        (
            "RC2_UPDATE_ISSUER",
            "update-issuer",
            "gocode.release.rc2-update-metadata-issuance/1",
            include_str!("../../../docs/schemas/rc2-update-metadata-issuance-v1.schema.json"),
        ),
        (
            "RC3_FINAL_REVIEWER",
            "final-review",
            "gocode.release.rc3-final-review/1",
            include_str!("../../../docs/schemas/rc3-final-review-v1.schema.json"),
        ),
    ];
    for (role, scope, id, bytes) in cases {
        assert_eq!(
            crate::receipt_v5_validation::allowed_payload_schemas(role, scope),
            vec![id.to_owned()]
        );
        let value: serde_json::Value =
            serde_json::from_str(bytes).expect("checked-in schema is valid JSON");
        assert_eq!(
            value.get("$id").and_then(serde_json::Value::as_str),
            Some(id)
        );
    }
}

#[test]
fn v4_leaf_pin_union_matches_checked_in_schema_files() {
    let manifest = env!("CARGO_MANIFEST_DIR");
    let files = [
        (
            "gocode.project-owner.authority-receipt/5",
            "project-owner-authority-receipt-v5.schema.json",
        ),
        (
            "gocode.project-owner.key-rotation/4",
            "project-owner-key-rotation-v4.schema.json",
        ),
        (
            "gocode.project-owner.publication-destination-allowlist/1",
            "project-owner-publication-destination-allowlist-v1.schema.json",
        ),
        (
            "gocode.project-owner.trust-config/4",
            "project-owner-trust-config-v4.schema.json",
        ),
        (
            "gocode.release.post-rc0-evidence-envelope/2",
            "release-post-rc0-evidence-envelope-v2.schema.json",
        ),
        (
            "gocode.release.post-rc0-stage-envelope/2",
            "release-post-rc0-stage-envelope-v2.schema.json",
        ),
        (
            "gocode.release.rc1-qualification-decision/1",
            "release-rc1-qualification-decision-v1.schema.json",
        ),
        (
            "gocode.release.rc2-native-evidence/1",
            "rc2-native-evidence-v1.schema.json",
        ),
        (
            "gocode.release.rc2-signing-authorization/1",
            "rc2-signing-authorization-v1.schema.json",
        ),
        (
            "gocode.release.rc2-signing-review/1",
            "rc2-signing-review-v1.schema.json",
        ),
        (
            "gocode.release.rc2-update-metadata-issuance/1",
            "rc2-update-metadata-issuance-v1.schema.json",
        ),
        (
            "gocode.release.rc3-final-review/1",
            "rc3-final-review-v1.schema.json",
        ),
        (
            "gocode.release.rc3-publication-authorization/2",
            "rc3-publication-authorization-v2.schema.json",
        ),
    ];
    let pins = crate::v4_trust_schema_digests().unwrap();
    assert_eq!(pins.len(), files.len());
    for (id, file) in files {
        let bytes = std::fs::read(format!("{manifest}/../../docs/schemas/{file}")).unwrap();
        let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(
            value.get("$id").and_then(serde_json::Value::as_str),
            Some(id)
        );
        let digest: [u8; 32] = Sha256::digest(&bytes).into();
        let pin = pins.iter().find(|p| p.schema_id == id).unwrap();
        assert_eq!(pin.schema_sha256, digest);
    }
}
