use ed25519_dalek::{Signer, SigningKey};
use gocode_project_owner_authority::{
    KeyRotationV1, ProjectOwnerTrustConfigV1, canonical_genesis_without_pop, framed_transcript,
    key_id, rotation_new_pop_payload, rotation_old_authorization_payload,
    v1_platform_scope_schema_digests,
};

pub const OLD_DOMAIN: &[u8] = b"gocode.project-owner.rotation-old-authorization/1";
pub const NEW_DOMAIN: &[u8] = b"gocode.project-owner.rotation-new-proof-of-possession/1";

#[must_use]
/// Build the deterministic valid genesis used by rotation tests.
///
/// # Panics
///
/// Panics only if fixed test-vector canonicalization or framing unexpectedly fails.
pub fn genesis() -> ProjectOwnerTrustConfigV1 {
    let key = SigningKey::from_bytes(&[7; 32]);
    let mut config = ProjectOwnerTrustConfigV1 {
        schema_version: "gocode.project-owner.trust-config/1".into(),
        repository_id: "gocode".into(),
        role: "PROJECT_OWNER".into(),
        epoch: 1,
        key_id: key_id(&key.verifying_key().to_bytes()),
        public_key: key.verifying_key().to_bytes(),
        schema_digests: v1_platform_scope_schema_digests(),
        proof_of_possession: [0; 64],
        predecessor: None,
    };
    config.proof_of_possession = key
        .sign(
            &framed_transcript(
                b"gocode.project-owner.genesis-pop/1",
                &canonical_genesis_without_pop(&config).expect("canonical genesis"),
            )
            .expect("frame"),
        )
        .to_bytes();
    config
}

#[must_use]
/// Build a deterministic valid rotation for the supplied test predecessor.
///
/// # Panics
///
/// Panics if the supplied test predecessor is not canonically serializable.
pub fn rotation(old: &ProjectOwnerTrustConfigV1) -> KeyRotationV1 {
    rotation_with_seed(old, [8; 32])
}

#[must_use]
/// Build a deterministic valid rotation to a key derived from `seed`.
///
/// # Panics
///
/// Panics if the supplied test predecessor is invalid or framing unexpectedly fails.
pub fn rotation_with_seed(old: &ProjectOwnerTrustConfigV1, seed: [u8; 32]) -> KeyRotationV1 {
    let old_seed = if old.epoch == 1 { [7; 32] } else { [8; 32] };
    let old_key = SigningKey::from_bytes(&old_seed);
    let new_key = SigningKey::from_bytes(&seed);
    let mut rotation = KeyRotationV1 {
        schema_version: "gocode.project-owner.key-rotation/1".into(),
        repository_id: "gocode".into(),
        role: "PROJECT_OWNER".into(),
        predecessor_config_sha256: old.sha256().expect("old sha"),
        old_key_id: old.key_id,
        old_epoch: old.epoch,
        new_key_id: key_id(&new_key.verifying_key().to_bytes()),
        new_public_key: new_key.verifying_key().to_bytes(),
        new_epoch: old.epoch + 1,
        old_authorization: [0; 64],
        new_proof_of_possession: [0; 64],
    };
    rotation.new_proof_of_possession = new_key
        .sign(
            &framed_transcript(
                NEW_DOMAIN,
                &rotation_new_pop_payload(old, &rotation).expect("new payload"),
            )
            .expect("frame"),
        )
        .to_bytes();
    rotation.old_authorization = old_key
        .sign(
            &framed_transcript(
                OLD_DOMAIN,
                &rotation_old_authorization_payload(&rotation).expect("old payload"),
            )
            .expect("frame"),
        )
        .to_bytes();
    rotation
}
