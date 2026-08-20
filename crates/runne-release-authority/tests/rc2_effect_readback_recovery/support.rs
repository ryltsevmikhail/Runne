use ed25519_dalek::SigningKey;
use runne_release_authority::{
    CanonicalPayloadKind, Digest, DurableFixturePromotionAuthority, InMemoryPromotionStore,
    PromotionId, RawRc2Evidence, ThresholdFixtureStoreBinding,
};
use serde_json::json;
use sha2::{Digest as _, Sha256};

#[path = "../canonical_wire/admission_support.rs"]
mod admission_support;
#[path = "../canonical_wire/metadata_support.rs"]
mod metadata_support;
#[path = "../verify_signed/support.rs"]
mod signing_support;
#[path = "../canonical_wire/support.rs"]
mod support;
#[path = "../verified_stage_support.rs"]
mod verified_stage_support;

pub const SLOT: &str = "linux-appimage";
pub const ARTIFACT: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

pub fn signing_authorized() -> (
    InMemoryPromotionStore,
    PromotionId,
    Vec<(CanonicalPayloadKind, Vec<u8>)>,
) {
    signing_support::signing_authorized()
}

pub fn uncertain_authority(
    name: &str,
) -> (
    std::path::PathBuf,
    DurableFixturePromotionAuthority,
    PromotionId,
    Vec<(CanonicalPayloadKind, Vec<u8>)>,
) {
    let path = path(name);
    let (memory, id, payloads) = signing_authorized();
    let mut authority = durable(&path, &memory);
    let lease = authority
        .reserve_rc2_signing_effects(&id, 4)
        .unwrap()
        .take(SLOT)
        .unwrap();
    let lease = authority.dispatch_rc2_signing_effects(&id, lease).unwrap();
    authority.uncertain_rc2_signing_effects(lease).unwrap();
    drop(authority);
    (path.clone(), reopen(&path), id, payloads)
}

pub fn readback(
    payloads: &[(CanonicalPayloadKind, Vec<u8>)],
    slot: &str,
    artifact: &str,
    outcome: &str,
    signature: u8,
) -> RawRc2Evidence {
    signed_readback(
        slot,
        &authorization(payloads),
        1,
        artifact,
        outcome,
        "runner",
        signature,
    )
}

pub fn authorization(payloads: &[(CanonicalPayloadKind, Vec<u8>)]) -> String {
    let raw = &payloads
        .iter()
        .find(|(kind, _)| *kind == CanonicalPayloadKind::Rc2Authorization)
        .unwrap()
        .1;
    digest(&raw[..raw.len() - 1])
}

pub fn signed_readback(
    slot: &str,
    authorization: &str,
    generation: u64,
    artifact: &str,
    outcome: &str,
    runner: &str,
    signature: u8,
) -> RawRc2Evidence {
    let mut raw = serde_json::to_vec(&json!({
        "schema_version":"gocode.release.rc2-signing-backend-readback/1", "signing_authorization_sha256":authorization,
        "artifact_slot_id":slot, "pre_sign_artifact_sha256":artifact, "effect_generation":generation,
        "outcome":outcome, "runner":identity(runner), "valid_from":1, "expires_at":2, "revocation_epoch":1,
    })).unwrap();
    raw.push(b'\n');
    RawRc2Evidence::signed(raw, &SigningKey::from_bytes(&[signature; 32]))
}

pub fn durable(
    path: &std::path::Path,
    memory: &InMemoryPromotionStore,
) -> DurableFixturePromotionAuthority {
    DurableFixturePromotionAuthority::create_from_in_memory(path, binding(), memory).unwrap()
}

pub fn reopen(path: &std::path::Path) -> DurableFixturePromotionAuthority {
    DurableFixturePromotionAuthority::reopen(path, binding()).unwrap()
}

pub fn cleanup(path: &std::path::Path) {
    let _ = std::fs::remove_file(path);
    let _ = std::fs::remove_file(path.with_extension("lease"));
}

fn identity(role: &str) -> serde_json::Value {
    json!({"principal_id":format!("{role}-principal"),"account_id":format!("{role}-account"),"lane_id":format!("{role}-lane"),"key_id":format!("{role}-key"),"signature_profile_id":format!("{role}-profile")})
}
fn binding() -> ThresholdFixtureStoreBinding {
    ThresholdFixtureStoreBinding::new(
        Digest::fixture(verified_stage_support::bootstrap_digest()),
        "fixture-v1",
        1,
    )
    .unwrap()
}
pub fn path(name: &str) -> std::path::PathBuf {
    let path =
        std::env::temp_dir().join(format!("runne-rc2-readback-{name}-{}", std::process::id()));
    cleanup(&path);
    path
}
fn digest(raw: &[u8]) -> String {
    let bytes: [u8; 32] = Sha256::digest(raw).into();
    bytes.iter().fold(String::new(), |mut output, byte| {
        use std::fmt::Write as _;
        write!(output, "{byte:02x}").expect("writing to a string cannot fail");
        output
    })
}
