use ed25519_dalek::{Signer as _, SigningKey};
use runne_project_owner_authority::{
    KeyRotationV2, KeyRotationV3, ProjectOwnerTrustConfigV1, ProjectOwnerTrustConfigV3,
    SchemaDigest, key_id, rotation_v2_new_pop_transcript, rotation_v2_old_authorization_transcript,
    rotation_v3_new_pop_transcript, rotation_v3_old_authorization_transcript,
    v2_platform_scope_schema_digests, v3_reconciliation_schema_digests, v3_trust_schema_digests,
    verify_trust_upgrade_v1_to_v2, verify_trust_upgrade_v2_to_v3,
};

fn v2_pins() -> Vec<SchemaDigest> {
    let mut pins = v2_platform_scope_schema_digests();
    pins.extend(v3_reconciliation_schema_digests());
    pins.sort_by(|left, right| left.schema_id.cmp(&right.schema_id));
    pins
}

fn old() -> (SigningKey, ProjectOwnerTrustConfigV1) {
    let key = SigningKey::from_bytes(&[7; 32]);
    let mut value = ProjectOwnerTrustConfigV1 {
        schema_version: "gocode.project-owner.trust-config/1".into(),
        repository_id: "gocode".into(),
        role: "PROJECT_OWNER".into(),
        epoch: 1,
        key_id: key_id(&key.verifying_key().to_bytes()),
        public_key: key.verifying_key().to_bytes(),
        schema_digests: v2_platform_scope_schema_digests(),
        proof_of_possession: [0; 64],
        predecessor: None,
    };
    value.proof_of_possession = key
        .sign(&runne_project_owner_authority::genesis_pop_transcript(&value).unwrap())
        .to_bytes();
    (key, value)
}

fn v2() -> (
    SigningKey,
    runne_project_owner_authority::VerifiedTrustConfigV2,
) {
    let (old_key, old) = old();
    let new_key = SigningKey::from_bytes(&[8; 32]);
    let mut rotation = KeyRotationV2 {
        schema_version: "gocode.project-owner.key-rotation/2".into(),
        repository_id: "gocode".into(),
        role: "PROJECT_OWNER".into(),
        old_trust_schema_version: old.schema_version.clone(),
        old_trust_config_sha256: old.sha256().unwrap(),
        old_key_id: old.key_id,
        old_epoch: old.epoch,
        new_trust_schema_version: "gocode.project-owner.trust-config/2".into(),
        new_key_id: key_id(&new_key.verifying_key().to_bytes()),
        new_public_key: new_key.verifying_key().to_bytes(),
        new_epoch: 2,
        new_schema_digests: v2_pins(),
        old_authorization: [0; 64],
        new_proof_of_possession: [0; 64],
    };
    rotation.new_proof_of_possession = new_key
        .sign(&rotation_v2_new_pop_transcript(&old, &rotation).unwrap())
        .to_bytes();
    rotation.old_authorization = old_key
        .sign(&rotation_v2_old_authorization_transcript(&rotation).unwrap())
        .to_bytes();
    (
        new_key,
        verify_trust_upgrade_v1_to_v2(&old, &rotation).unwrap(),
    )
}

#[test]
fn v3_upgrades_v2_only_with_the_exact_finalized_pin_union() {
    let (old_key, old) = v2();
    let new_key = SigningKey::from_bytes(&[9; 32]);
    let mut rotation = KeyRotationV3 {
        schema_version: "gocode.project-owner.key-rotation/3".into(),
        repository_id: "gocode".into(),
        role: "PROJECT_OWNER".into(),
        old_trust_schema_version: old.schema_version.clone(),
        old_trust_config_sha256: old.sha256().unwrap(),
        old_key_id: old.key_id,
        old_epoch: old.epoch,
        new_trust_schema_version: "gocode.project-owner.trust-config/3".into(),
        new_key_id: key_id(&new_key.verifying_key().to_bytes()),
        new_public_key: new_key.verifying_key().to_bytes(),
        new_epoch: 3,
        new_schema_digests: v3_trust_schema_digests().unwrap(),
        old_authorization: [0; 64],
        new_proof_of_possession: [0; 64],
    };
    rotation.new_proof_of_possession = new_key
        .sign(&rotation_v3_new_pop_transcript(&old, &rotation).unwrap())
        .to_bytes();
    rotation.old_authorization = old_key
        .sign(&rotation_v3_old_authorization_transcript(&rotation).unwrap())
        .to_bytes();
    assert!(verify_trust_upgrade_v2_to_v3(&old, &rotation).is_ok());
    for mutate in [
        |value: &mut KeyRotationV3| {
            value.new_schema_digests.pop();
        },
        |value: &mut KeyRotationV3| {
            value.new_schema_digests.push(SchemaDigest {
                schema_id: "gocode.extra/1".into(),
                schema_sha256: [0; 32],
            });
        },
    ] {
        let mut changed = rotation.clone();
        mutate(&mut changed);
        assert!(verify_trust_upgrade_v2_to_v3(&old, &changed).is_err());
    }
}

#[test]
fn v3_raw_codec_requires_exact_canonical_bytes() {
    let (_, old) = v2();
    let key = SigningKey::from_bytes(&[9; 32]);
    let mut trust = ProjectOwnerTrustConfigV3 {
        schema_version: "gocode.project-owner.trust-config/3".into(),
        repository_id: "gocode".into(),
        role: "PROJECT_OWNER".into(),
        epoch: 3,
        key_id: key_id(&key.verifying_key().to_bytes()),
        public_key: key.verifying_key().to_bytes(),
        schema_digests: v3_trust_schema_digests().unwrap(),
        proof_of_possession: [0; 64],
        predecessor: old.sha256().unwrap(),
        predecessor_schema_version: old.schema_version.clone(),
    };
    trust.proof_of_possession = key
        .sign(
            &runne_project_owner_authority::framed_transcript(
                b"gocode.project-owner.rotation-new-proof-of-possession/3",
                &runne_project_owner_authority::canonical_config_v3(&trust, false).unwrap(),
            )
            .unwrap(),
        )
        .to_bytes();
    let bytes = trust.to_canonical_json().unwrap();
    assert_eq!(ProjectOwnerTrustConfigV3::from_json(&bytes).unwrap(), trust);
    assert!(ProjectOwnerTrustConfigV3::from_json(&bytes[..bytes.len() - 1]).is_err());
}
