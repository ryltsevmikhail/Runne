use ed25519_dalek::{Signer as _, SigningKey};
use runne_project_owner_authority::{
    KeyRotationV2, ProjectOwnerTrustConfigV1, SchemaDigest, key_id,
    v2_platform_scope_schema_digests, v3_reconciliation_schema_digests, verify_rotation_v2,
    verify_trust_upgrade_v1_to_v2,
};
use sha2::{Digest, Sha256};
use std::path::Path;

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

#[test]
fn v2_rotation_preserves_the_exact_pins() {
    let (old_key, old) = old();
    let first_key = SigningKey::from_bytes(&[8; 32]);
    let mut first = KeyRotationV2 {
        schema_version: "gocode.project-owner.key-rotation/2".into(),
        repository_id: "gocode".into(),
        role: "PROJECT_OWNER".into(),
        old_trust_schema_version: old.schema_version.clone(),
        old_trust_config_sha256: old.sha256().unwrap(),
        old_key_id: old.key_id,
        old_epoch: 1,
        new_trust_schema_version: "gocode.project-owner.trust-config/2".into(),
        new_key_id: key_id(&first_key.verifying_key().to_bytes()),
        new_public_key: first_key.verifying_key().to_bytes(),
        new_epoch: 2,
        new_schema_digests: pins(),
        old_authorization: [0; 64],
        new_proof_of_possession: [0; 64],
    };
    first.new_proof_of_possession = first_key
        .sign(&runne_project_owner_authority::rotation_v2_new_pop_transcript(&old, &first).unwrap())
        .to_bytes();
    first.old_authorization = old_key
        .sign(
            &runne_project_owner_authority::rotation_v2_old_authorization_transcript(&first)
                .unwrap(),
        )
        .to_bytes();
    let v2 = verify_trust_upgrade_v1_to_v2(&old, &first).unwrap();
    let next_key = SigningKey::from_bytes(&[9; 32]);
    let mut second = KeyRotationV2 {
        schema_version: "gocode.project-owner.key-rotation/2".into(),
        repository_id: "gocode".into(),
        role: "PROJECT_OWNER".into(),
        old_trust_schema_version: v2.schema_version.clone(),
        old_trust_config_sha256: v2.sha256().unwrap(),
        old_key_id: v2.key_id,
        old_epoch: v2.epoch,
        new_trust_schema_version: "gocode.project-owner.trust-config/2".into(),
        new_key_id: key_id(&next_key.verifying_key().to_bytes()),
        new_public_key: next_key.verifying_key().to_bytes(),
        new_epoch: 3,
        new_schema_digests: pins(),
        old_authorization: [0; 64],
        new_proof_of_possession: [0; 64],
    };
    second.new_proof_of_possession = next_key
        .sign(
            &runne_project_owner_authority::rotation_v2_successor_pop_transcript(&v2, &second)
                .unwrap(),
        )
        .to_bytes();
    second.old_authorization = first_key
        .sign(
            &runne_project_owner_authority::rotation_v2_old_authorization_transcript(&second)
                .unwrap(),
        )
        .to_bytes();
    assert_eq!(
        verify_rotation_v2(&v2, &second).unwrap().schema_digests,
        pins()
    );
}

fn pins() -> Vec<SchemaDigest> {
    let mut pins = v2_platform_scope_schema_digests();
    pins.extend(v3_reconciliation_schema_digests());
    pins.sort_by(|a, b| a.schema_id.cmp(&b.schema_id));
    pins
}

#[test]
fn target_schema_pins_match_the_exact_schema_files() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let expected = [
        (
            "gocode.governance.v1-platform-scope-decision/1",
            "docs/schemas/v1-platform-scope-decision-v1.schema.json",
        ),
        (
            "gocode.project-owner.authority-receipt/2",
            "docs/schemas/project-owner-authority-receipt-v2.schema.json",
        ),
        (
            "gocode.project-owner.authority-receipt/3",
            "docs/schemas/project-owner-authority-receipt-v3.schema.json",
        ),
        (
            "gocode.rc0.post-rc0-platform-composed-universe/1",
            "docs/schemas/post-rc0-platform-composed-universe-v1.schema.json",
        ),
        (
            "gocode.v1-platform-scope-claim-migration/1",
            "docs/schemas/v1-platform-scope-claim-migration-v1.schema.json",
        ),
    ];
    for (pin, (schema_id, relative_path)) in pins().iter().zip(expected) {
        assert_eq!(pin.schema_id, schema_id);
        assert_eq!(
            pin.schema_sha256,
            Sha256::digest(std::fs::read(root.join(relative_path)).unwrap()).as_slice()
        );
    }
}

#[test]
fn v1_to_v2_requires_exact_monotonic_pins_and_distinct_key() {
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
        new_schema_digests: pins(),
        old_authorization: [0; 64],
        new_proof_of_possession: [0; 64],
    };
    rotation.new_proof_of_possession = new_key
        .sign(
            &runne_project_owner_authority::rotation_v2_new_pop_transcript(&old, &rotation)
                .unwrap(),
        )
        .to_bytes();
    rotation.old_authorization = old_key
        .sign(
            &runne_project_owner_authority::rotation_v2_old_authorization_transcript(&rotation)
                .unwrap(),
        )
        .to_bytes();
    let successor = verify_trust_upgrade_v1_to_v2(&old, &rotation).unwrap();
    assert_eq!(successor.predecessor, old.sha256().unwrap());
    assert_eq!(
        successor.predecessor_schema_version,
        "gocode.project-owner.trust-config/1"
    );
    assert_eq!(successor.schema_digests, pins());
    let mut injected = rotation;
    injected.new_schema_digests.push(SchemaDigest {
        schema_id: "gocode.extra/1".into(),
        schema_sha256: [9; 32],
    });
    assert!(verify_trust_upgrade_v1_to_v2(&old, &injected).is_err());
}
