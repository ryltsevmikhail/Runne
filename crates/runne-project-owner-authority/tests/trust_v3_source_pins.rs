//! V3 trust pins bind exact checked-in JSON Schema bytes.

use std::{collections::BTreeMap, fs, path::Path};

use runne_project_owner_authority::v3_trust_schema_digests;
use sha2::{Digest, Sha256};

const SOURCES: [(&str, &str); 17] = [
    (
        "gocode.governance.v1-platform-scope-decision/1",
        "v1-platform-scope-decision-v1.schema.json",
    ),
    (
        "gocode.project-owner.authority-receipt/2",
        "project-owner-authority-receipt-v2.schema.json",
    ),
    (
        "gocode.project-owner.authority-receipt/3",
        "project-owner-authority-receipt-v3.schema.json",
    ),
    (
        "gocode.project-owner.authority-receipt/4",
        "project-owner-authority-receipt-v4.schema.json",
    ),
    (
        "gocode.rc0.post-rc0-platform-composed-universe/1",
        "post-rc0-platform-composed-universe-v1.schema.json",
    ),
    (
        "gocode.release.post-rc0-stage-envelope/1",
        "release-post-rc0-stage-envelope-v1.schema.json",
    ),
    (
        "gocode.release.promotion-state-snapshot/1",
        "promotion-state-snapshot-v1.schema.json",
    ),
    (
        "gocode.release.publication-manifest/1",
        "publication-manifest-v1.schema.json",
    ),
    (
        "gocode.release.rc1-qualification-decision/1",
        "release-rc1-qualification-decision-v1.schema.json",
    ),
    (
        "gocode.release.rc2-signed-artifact-record/1",
        "release-rc2-signed-artifact-record-v1.schema.json",
    ),
    (
        "gocode.release.rc2-signing-authorization/1",
        "rc2-signing-authorization-v1.schema.json",
    ),
    (
        "gocode.release.rc2-threshold-update-metadata-set/1",
        "release-rc2-threshold-update-metadata-set-v1.schema.json",
    ),
    (
        "gocode.release.rc3-publication-authorization/1",
        "rc3-publication-authorization-v1.schema.json",
    ),
    (
        "gocode.release.signed-envelope-inventory/1",
        "signed-envelope-inventory-v1.schema.json",
    ),
    (
        "gocode.release.signed-envelope-verification-report/1",
        "signed-envelope-verification-report-v1.schema.json",
    ),
    (
        "gocode.release.unsigned-candidate-manifest/1",
        "unsigned-candidate-manifest-v1.schema.json",
    ),
    (
        "gocode.v1-platform-scope-claim-migration/1",
        "v1-platform-scope-claim-migration-v1.schema.json",
    ),
];

#[test]
fn frozen_v3_rc2_record_source_pin_matches_legacy_bytes() {
    let bytes =
        include_bytes!("../../../docs/schemas/release-rc2-signed-artifact-record-v1.schema.json");
    assert_eq!(bytes.len(), 2218);
    assert_eq!(
        format!("{:x}", Sha256::digest(bytes)),
        "bfa6908bf65be56d733faad09168bdf7e6033bacc924695b48d6655dc39a112b"
    );
}

#[test]
fn frozen_v4_program_source_pin_matches_legacy_bytes() {
    let bytes = include_bytes!(
        "../../../docs/superpowers/specs/2026-08-09-post-rc0-delivery-program-design.md"
    );
    assert_eq!(bytes.len(), 26_202);
    assert_eq!(
        format!("{:x}", Sha256::digest(bytes)),
        "281599b27a9c578291527ca6e056de9369073e006687dd1149420d83a2cc86b9"
    );
}

#[test]
fn finalized_v3_pins_hash_each_real_schema_file() {
    let schema_root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../docs/schemas");
    let actual = v3_trust_schema_digests()
        .unwrap()
        .into_iter()
        .map(|pin| (pin.schema_id, pin.schema_sha256))
        .collect::<BTreeMap<_, _>>();
    let expected = SOURCES
        .into_iter()
        .map(|(schema_id, filename)| {
            let bytes = fs::read(schema_root.join(filename)).unwrap();
            (schema_id.to_owned(), Sha256::digest(bytes).into())
        })
        .collect::<BTreeMap<String, [u8; 32]>>();
    assert_eq!(actual, expected);
}
