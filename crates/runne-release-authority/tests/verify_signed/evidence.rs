#![allow(unused_imports)] // Raw fixture vectors are selectively composed by integration binaries.

use ed25519_dalek::SigningKey;
use runne_release_authority::{
    CanonicalPayloadKind, FixtureEvidenceKeyRegistration, FixtureEvidenceTrustState,
    InspectedCanonicalPayload, RawRc2Evidence,
};
use serde_json::{Value, json};

pub(super) fn trust() -> FixtureEvidenceTrustState {
    FixtureEvidenceTrustState::try_new(
        1,
        1,
        1,
        ["signer", "runner", "reviewer", "issuer"]
            .into_iter()
            .zip([7, 8, 9, 10])
            .map(|(role, seed)| {
                FixtureEvidenceKeyRegistration::new(
                    &format!("{role}-principal"),
                    &format!("{role}-account"),
                    &format!("{role}-lane"),
                    &format!("{role}-key"),
                    &format!("{role}-profile"),
                    SigningKey::from_bytes(&[seed; 32])
                        .verifying_key()
                        .to_bytes(),
                )
            })
            .collect(),
    )
    .unwrap()
}
fn raw(value: &Value, seed: u8) -> RawRc2Evidence {
    let mut raw = serde_json::to_vec(&value).unwrap();
    raw.push(b'\n');
    RawRc2Evidence::signed(raw, &SigningKey::from_bytes(&[seed; 32]))
}
fn identity(role: &str) -> Value {
    json!({"principal_id":format!("{role}-principal"),"account_id":format!("{role}-account"),"lane_id":format!("{role}-lane"),"key_id":format!("{role}-key"),"signature_profile_id":format!("{role}-profile")})
}
pub(super) fn claim(
    record: &InspectedCanonicalPayload,
    auth: &InspectedCanonicalPayload,
    slot: &str,
    platform: &str,
    length: u64,
) -> RawRc2Evidence {
    claim_with_expiry(record, auth, slot, platform, length, 2)
}
pub(super) fn claim_with_expiry(
    record: &InspectedCanonicalPayload,
    _auth: &InspectedCanonicalPayload,
    slot: &str,
    platform: &str,
    length: u64,
    expires_at: u64,
) -> RawRc2Evidence {
    let record: Value = serde_json::from_slice(record.raw()).unwrap();
    raw(
        &json!({"schema_version":"gocode.release.rc2-signing-effect-claim/1","signing_authorization_sha256":record["signing_authorization_sha256"],"parent_candidate_sha256":record["parent_candidate_sha256"],"artifact_slot_id":slot,"platform":platform,"pre_sign_artifact_sha256":record["pre_sign_artifact_sha256"],"pre_sign_artifact_length":length,"signer":identity("signer"),"runner":identity("runner"),"workflow_sha256":record["workflow_sha256"],"effect_namespace":"namespace","effect_generation":1,"generation_fence":1,"operation":"native_sign","valid_from":1,"expires_at":expires_at,"revocation_epoch":1}),
        7,
    )
}
pub(super) fn native(
    record: &InspectedCanonicalPayload,
    effect: &runne_release_authority::FixtureVerifiedSigningEffect,
    platform: &str,
) -> RawRc2Evidence {
    native_with_expiry(record, effect, platform, 2)
}
pub(super) fn native_with_expiry(
    record: &InspectedCanonicalPayload,
    effect: &runne_release_authority::FixtureVerifiedSigningEffect,
    platform: &str,
    expires_at: u64,
) -> RawRc2Evidence {
    let record_digest = digest(&record.raw()[..record.raw().len() - 1]);
    let record: Value = serde_json::from_slice(record.raw()).unwrap();
    let digests = ["a", "b", "c", "d", "e", "f", "1", "2", "3", "4"];
    raw(
        &json!({"schema_version":"gocode.release.rc2-native-evidence/1","signed_artifact_record_sha256":record_digest,"signing_effect_claim_sha256":effect_digest(effect),"parent_candidate_sha256":record["parent_candidate_sha256"],"artifact_slot_id":record["artifact_slot_id"],"platform":platform,"host_id":"host","build_id":"build","architecture":"x86_64","post_sign_artifact_sha256":record["artifact_sha256"],"post_sign_artifact_length":record["artifact_length"],"attestations":attestations(record["artifact_sha256"].as_str().unwrap(), &digests),"runner":identity("runner"),"result":"verified","valid_from":1,"expires_at":expires_at,"revocation_epoch":1}),
        8,
    )
}
fn attestations(artifact: &str, digests: &[&str; 10]) -> Vec<Value> {
    ["native_signature", "certificate_chain", "timestamp", "secret_scan", "advisory_scan", "package_inspection", "install", "upgrade", "rollback", "uninstall"]
        .into_iter()
        .zip(digests)
        .map(|(kind, digest)| json!({"kind":kind,"result":"verified","artifact_sha256":artifact,"result_sha256":digest.repeat(64)}))
        .collect()
}
pub(super) fn review(
    auth: &InspectedCanonicalPayload,
    inventory: &InspectedCanonicalPayload,
    native: &[runne_release_authority::FixtureVerifiedNativeEvidence; 3],
) -> RawRc2Evidence {
    raw(
        &json!({"schema_version":"gocode.release.rc2-signing-review/1","signing_authorization_sha256":digest(&auth.raw()[..auth.raw().len()-1]),"inventory_sha256":digest(&inventory.raw()[..inventory.raw().len()-1]),"native_evidence_sha256":native.iter().map(native_digest).collect::<Vec<_>>(),"reviewer":identity("reviewer"),"approval":"approved","valid_from":1,"expires_at":2,"revocation_epoch":1}),
        9,
    )
}
pub(super) fn issuance(
    auth: &InspectedCanonicalPayload,
    inventory: &InspectedCanonicalPayload,
    metadata: &InspectedCanonicalPayload,
) -> RawRc2Evidence {
    raw(
        &json!({"schema_version":"gocode.release.rc2-update-metadata-issuance/1","signing_authorization_sha256":digest(&auth.raw()[..auth.raw().len()-1]),"inventory_sha256":digest(&inventory.raw()[..inventory.raw().len()-1]),"threshold_metadata_sha256":digest(&metadata.raw()[..metadata.raw().len()-1]),"update_issuer":identity("issuer"),"root_key_ids":key_ids(metadata,"root"),"targets_key_ids":key_ids(metadata,"targets"),"root_threshold":2,"targets_threshold":2,"issuance":"issued","valid_from":1,"expires_at":2,"revocation_epoch":1}),
        10,
    )
}
fn key_ids(metadata: &InspectedCanonicalPayload, role: &str) -> Vec<String> {
    serde_json::from_slice::<Value>(metadata.raw()).unwrap()[role]["body"]["keyset"]
        .as_array()
        .unwrap()
        .iter()
        .map(|key| key["key_id"].as_str().unwrap().into())
        .collect()
}
fn digest(raw: &[u8]) -> String {
    use sha2::{Digest as _, Sha256};
    let bytes: [u8; 32] = Sha256::digest(raw).into();
    let mut output = String::with_capacity(64);
    for byte in bytes {
        use std::fmt::Write as _;
        write!(output, "{byte:02x}").unwrap();
    }
    output
}
fn effect_digest(value: &runne_release_authority::FixtureVerifiedSigningEffect) -> String {
    value.sha256().to_hex()
}
fn native_digest(value: &runne_release_authority::FixtureVerifiedNativeEvidence) -> String {
    value.sha256().to_hex()
}
