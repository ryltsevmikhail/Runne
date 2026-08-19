use super::{metadata_support, support};
use runne_release_authority::CanonicalPayloadKind;
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};

const POST: &str = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";

pub fn admission_payloads() -> Vec<(CanonicalPayloadKind, Vec<u8>)> {
    admission_payloads_for(&"aa".repeat(32), &"aa".repeat(32))
}

pub fn admission_payloads_for(
    bootstrap_sha256: &str,
    candidate_binding_sha256: &str,
) -> Vec<(CanonicalPayloadKind, Vec<u8>)> {
    let manifest = replace(
        CanonicalPayloadKind::UnsignedManifest,
        [("bootstrap_sha256", json!(bootstrap_sha256))],
    );
    let rc1 = replace(
        CanonicalPayloadKind::Rc1Decision,
        [
            ("bootstrap_sha256", json!(bootstrap_sha256)),
            ("candidate_binding_sha256", json!(candidate_binding_sha256)),
            ("release_facts_sha256", json!(hex(&manifest))),
        ],
    );
    let rc2 = replace(
        CanonicalPayloadKind::Rc2Authorization,
        [
            ("unsigned_manifest_sha256", json!(hex(&manifest))),
            (
                "pre_sign_artifacts",
                json!([
                    {"artifact_slot_id":"linux-appimage","platform":"linux","operation":"native_sign","expected_artifact_sha256":"aa".repeat(32),"expected_artifact_length":1},
                    {"artifact_slot_id":"linux-deb","platform":"linux","operation":"native_sign","expected_artifact_sha256":"aa".repeat(32),"expected_artifact_length":2},
                    {"artifact_slot_id":"windows-installer-unsigned","platform":"windows","operation":"native_sign","expected_artifact_sha256":"aa".repeat(32),"expected_artifact_length":5}
                ]),
            ),
        ],
    );
    let linux_appimage = record("linux-appimage", "linux", &rc2, &"aa".repeat(32), 1, 11);
    let linux_deb = record("linux-deb", "linux", &rc2, &"aa".repeat(32), 2, 22);
    let windows = record(
        "windows-installer-unsigned",
        "windows",
        &rc2,
        &"aa".repeat(32),
        5,
        55,
    );
    let records = [hex(&linux_appimage), hex(&linux_deb), hex(&windows)];
    let inventory = replace(
        CanonicalPayloadKind::Inventory,
        [("artifact_records", json!(records))],
    );
    let metadata = metadata_support::threshold_metadata_for_inventory(&hex(&inventory));
    let report = replace(
        CanonicalPayloadKind::VerificationReport,
        [
            ("inventory_sha256", json!(hex(&inventory))),
            ("metadata_set_sha256", json!(hex(&metadata))),
        ],
    );
    let publication = replace(
        CanonicalPayloadKind::PublicationManifest,
        [
            ("inventory_sha256", json!(hex(&inventory))),
            ("metadata_set_sha256", json!(hex(&metadata))),
            ("report_sha256", json!(hex(&report))),
        ],
    );
    let rc3 = replace(
        CanonicalPayloadKind::Rc3Authorization,
        [
            ("inventory_sha256", json!(hex(&inventory))),
            ("report_sha256", json!(hex(&report))),
            ("publication_manifest_sha256", json!(hex(&publication))),
        ],
    );
    vec![
        (CanonicalPayloadKind::Rc1Decision, rc1),
        (CanonicalPayloadKind::UnsignedManifest, manifest),
        (CanonicalPayloadKind::Rc2Authorization, rc2),
        (CanonicalPayloadKind::ArtifactRecord, linux_appimage),
        (CanonicalPayloadKind::ArtifactRecord, linux_deb),
        (CanonicalPayloadKind::ArtifactRecord, windows),
        (CanonicalPayloadKind::ThresholdMetadata, metadata),
        (CanonicalPayloadKind::Inventory, inventory),
        (CanonicalPayloadKind::VerificationReport, report),
        (CanonicalPayloadKind::PublicationManifest, publication),
        (CanonicalPayloadKind::Rc3Authorization, rc3),
    ]
}

fn record(
    slot: &str,
    platform: &str,
    authorization: &[u8],
    pre_sign: &str,
    pre_length: u64,
    post_length: u64,
) -> Vec<u8> {
    replace(
        CanonicalPayloadKind::ArtifactRecord,
        [
            ("platform", json!(platform)),
            ("artifact_slot_id", json!(slot)),
            (
                "signing_authorization_sha256",
                json!(hex(&authorization[..authorization.len() - 1])),
            ),
            ("pre_sign_artifact_sha256", json!(pre_sign)),
            ("pre_sign_artifact_length", json!(pre_length)),
            ("artifact_sha256", json!(POST)),
            ("artifact_length", json!(post_length)),
        ],
    )
}

#[allow(dead_code)]
pub fn payloads_with_bad_metadata_link() -> Vec<(CanonicalPayloadKind, Vec<u8>)> {
    admission_payloads()
        .into_iter()
        .map(|(kind, raw)| {
            if kind == CanonicalPayloadKind::ThresholdMetadata {
                (
                    kind,
                    replace(kind, [("inventory_sha256", json!("bb".repeat(32)))]),
                )
            } else {
                (kind, raw)
            }
        })
        .collect()
}

#[allow(dead_code)]
pub fn payloads_with_pre_sign_metadata_targets() -> Vec<(CanonicalPayloadKind, Vec<u8>)> {
    with_pre_sign_metadata_targets(admission_payloads())
}

pub fn with_pre_sign_metadata_targets(
    mut payloads: Vec<(CanonicalPayloadKind, Vec<u8>)>,
) -> Vec<(CanonicalPayloadKind, Vec<u8>)> {
    let inventory = payloads
        .iter()
        .find(|(kind, _)| *kind == CanonicalPayloadKind::Inventory)
        .unwrap();
    let pre = "aa".repeat(32);
    let mut metadata = serde_json::to_vec(&support::threshold_fixture::metadata_with_targets(
        &hex(&inventory.1),
        [(&pre, 1), (&pre, 2), (&pre, 5)],
    ))
    .unwrap();
    metadata.push(b'\n');
    let metadata_digest = hex(&metadata);
    for (kind, raw) in &mut payloads {
        if *kind == CanonicalPayloadKind::ThresholdMetadata {
            raw.clone_from(&metadata);
        }
        if *kind == CanonicalPayloadKind::VerificationReport {
            let mut value: serde_json::Value = serde_json::from_slice(raw).unwrap();
            value["metadata_set_sha256"] = json!(metadata_digest);
            *raw = serde_json::to_vec(&value).unwrap();
            raw.push(b'\n');
        }
    }
    payloads
}

fn replace<const N: usize>(kind: CanonicalPayloadKind, values: [(&str, Value); N]) -> Vec<u8> {
    let mut value: serde_json::Map<String, Value> =
        serde_json::from_slice(&support::payload(kind)).unwrap();
    for (key, replacement) in values {
        value.insert(key.into(), replacement);
    }
    let mut raw = serde_json::to_vec(&Value::Object(value)).unwrap();
    raw.push(b'\n');
    raw
}
fn hex(raw: &[u8]) -> String {
    hash(raw.strip_suffix(b"\n").unwrap_or(raw))
}
fn hash(raw: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let digest = Sha256::digest(raw);
    let mut output = String::with_capacity(64);
    for byte in digest {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}
