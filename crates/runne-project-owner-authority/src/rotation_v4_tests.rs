use ed25519_dalek::{Signer as _, SigningKey};

use crate::{
    KeyRotationV4, ProjectOwnerTrustConfigV3, canonical_config_v3, key_id,
    rotation_v4_new_pop_transcript, rotation_v4_old_authorization_transcript,
    verify_trust_upgrade_v3_to_v4,
};

#[test]
fn verified_v3_rotation_mints_only_a_proof_bound_v4_successor() {
    let old_key = SigningKey::from_bytes(&[31; 32]);
    let mut old = ProjectOwnerTrustConfigV3 {
        schema_version: crate::trust_v3::CONFIG_SCHEMA_V3.into(),
        repository_id: "gocode".into(),
        role: "PROJECT_OWNER".into(),
        epoch: 3,
        key_id: key_id(&old_key.verifying_key().to_bytes()),
        public_key: old_key.verifying_key().to_bytes(),
        schema_digests: crate::v3_trust_schema_digests().unwrap(),
        proof_of_possession: [0; 64],
        predecessor: [1; 32],
        predecessor_schema_version: "gocode.project-owner.trust-config/2".into(),
    };
    old.proof_of_possession = old_key
        .sign(
            &crate::framed_transcript(
                crate::trust_v3::POP_DOMAIN_V3,
                &canonical_config_v3(&old, false).unwrap(),
            )
            .unwrap(),
        )
        .to_bytes();
    let verified = crate::trust_v3::verified_v3(old.clone());
    let new_key = SigningKey::from_bytes(&[32; 32]);
    let mut rotation = KeyRotationV4 {
        schema_version: "gocode.project-owner.key-rotation/4".into(),
        repository_id: "gocode".into(),
        role: "PROJECT_OWNER".into(),
        old_trust_schema_version: old.schema_version.clone(),
        old_trust_config_sha256: old.sha256().unwrap(),
        old_key_id: old.key_id,
        old_epoch: 3,
        new_trust_schema_version: crate::trust_v4::CONFIG_SCHEMA_V4.into(),
        new_key_id: key_id(&new_key.verifying_key().to_bytes()),
        new_public_key: new_key.verifying_key().to_bytes(),
        new_epoch: 4,
        new_schema_digests: crate::v4_trust_schema_digests().unwrap(),
        old_authorization: [0; 64],
        new_proof_of_possession: [0; 64],
    };
    rotation.new_proof_of_possession = new_key
        .sign(&rotation_v4_new_pop_transcript(&old, &rotation).unwrap())
        .to_bytes();
    rotation.old_authorization = old_key
        .sign(&rotation_v4_old_authorization_transcript(&rotation).unwrap())
        .to_bytes();
    let successor = verify_trust_upgrade_v3_to_v4(&verified, &rotation).unwrap();
    assert_eq!(successor.epoch, 4);
    assert_eq!(successor.public_key, new_key.verifying_key().to_bytes());
}
