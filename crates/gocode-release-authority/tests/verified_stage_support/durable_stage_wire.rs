use std::fmt::Write as _;

use sha2::{Digest as _, Sha256};

/// Rewrites a claim and its admission fingerprint in a durable fixture wire.
///
/// # Panics
///
/// Panics when the fixture wire is not a canonical stage-claim record.
pub fn rewrite_stage_claim_role_floor(path: &std::path::Path, role_floor: u64) {
    let mut record: serde_json::Value =
        serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
    let claim = record["promotions"]
        .as_array_mut()
        .unwrap()
        .first_mut()
        .unwrap()["record"]["stage_claims"]
        .as_array_mut()
        .unwrap()
        .first_mut()
        .unwrap();
    assert_eq!(
        claim["admission_fingerprint"].as_str().unwrap(),
        stage_admission_fingerprint(claim)
    );
    let old_fingerprint = claim["admission_fingerprint"].as_str().unwrap().to_owned();
    claim["role_floor"] = role_floor.into();
    let fingerprint = stage_admission_fingerprint(claim);
    replace_after(
        path,
        "\"stage_claims\"",
        "\"role_floor\":1",
        &format!("\"role_floor\":{role_floor}"),
    );
    replace_after(
        path,
        "\"stage_claims\"",
        &format!("\"admission_fingerprint\":\"{old_fingerprint}\""),
        &format!("\"admission_fingerprint\":\"{fingerprint}\""),
    );
}

fn replace_after(path: &std::path::Path, start: &str, needle: &str, replacement: &str) {
    let text = String::from_utf8(std::fs::read(path).unwrap()).unwrap();
    let (head, tail) = text.split_once(start).unwrap();
    assert!(tail.contains(needle));
    std::fs::write(
        path,
        format!("{head}{start}{}", tail.replacen(needle, replacement, 1)),
    )
    .unwrap();
}

fn stage_admission_fingerprint(claim: &serde_json::Value) -> String {
    let bytes = |name| decode_hex(claim[name].as_str().unwrap());
    let text = |name| claim[name].as_str().unwrap().as_bytes();
    let u64 = |name| claim[name].as_u64().unwrap().to_be_bytes();
    let fingerprint = bytes("fingerprint");
    let root_epoch = u64("root_epoch");
    let envelope_epoch = u64("envelope_epoch");
    let payload_valid_from = u64("payload_valid_from");
    let payload_expires_at = u64("payload_expires_at");
    let payload_epoch = u64("payload_epoch");
    let revision = u64("revision");
    let role_floor = u64("role_floor");
    let fields: [&[u8]; 21] = [
        b"gocode.release.stage-admission-command/1\0",
        &bytes("bootstrap"),
        text("role"),
        &bytes("payload"),
        text("nonce"),
        &bytes("envelope"),
        text("bootstrap_not_before"),
        text("bootstrap_expires_at"),
        &root_epoch,
        text("envelope_not_before"),
        text("envelope_expires_at"),
        &envelope_epoch,
        &payload_valid_from,
        &payload_expires_at,
        &payload_epoch,
        text("promotion"),
        &revision,
        text("command"),
        text("kind"),
        &fingerprint,
        &role_floor,
    ];
    let mut transcript = Vec::new();
    for field in fields {
        transcript.extend_from_slice(&(field.len() as u64).to_be_bytes());
        transcript.extend_from_slice(field);
    }
    let mut hex = String::with_capacity(64);
    for byte in Sha256::digest(transcript) {
        write!(hex, "{byte:02x}").unwrap();
    }
    hex
}

fn decode_hex(value: &str) -> Vec<u8> {
    (0..value.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&value[index..index + 2], 16).unwrap())
        .collect()
}
