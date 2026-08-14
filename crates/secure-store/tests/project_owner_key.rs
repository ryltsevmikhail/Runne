#![cfg(not(target_os = "macos"))]

use ed25519_dalek::SigningKey;
use gocode_secure_store::{
    MAX_PROJECT_OWNER_TRANSCRIPT_BYTES, PendingProjectOwnerKey, ProjectOwnerAnchorFloor,
    ProjectOwnerKeyMaterial, ProjectOwnerKeyRef, ProjectOwnerKeyStore, StoreStatus, StubStore,
    validate_transcript,
};
use zeroize::Zeroizing;

fn key_ref() -> ProjectOwnerKeyRef {
    ProjectOwnerKeyRef::new(
        "gocode",
        SigningKey::from_bytes(&[7; 32]).verifying_key().to_bytes(),
        1,
    )
    .expect("valid reference")
}

#[test]
fn non_macos_stub_denies_every_project_owner_key_operation() {
    let store = StubStore::new();
    let reference = key_ref();
    let floor = ProjectOwnerAnchorFloor::new("gocode", 1, [8; 32]).expect("floor");

    let mut build_pop =
        |_key: &ProjectOwnerKeyRef| -> Result<Vec<u8>, StoreStatus> { Ok(Vec::new()) };
    assert!(matches!(
        store.create_pending(None, "gocode", 1, &mut build_pop),
        Err(StoreStatus::Unsupported)
    ));
    assert!(matches!(
        store.create_or_resume_pending(None, "gocode", 1, &mut build_pop),
        Err(StoreStatus::Unsupported)
    ));
    assert_eq!(
        store.sign_active(&reference, b"bounded transcript"),
        Err(StoreStatus::Unsupported)
    );
    assert_eq!(
        store.read_anchor_floor("gocode"),
        Err(StoreStatus::Unsupported)
    );
    assert_eq!(
        store.read_active_ref("gocode"),
        Err(StoreStatus::Unsupported)
    );
    assert_eq!(
        store.write_anchor_floor(None, &floor),
        Err(StoreStatus::Unsupported)
    );
    assert!(matches!(
        store.export_active_for_backup(&reference),
        Err(StoreStatus::Unsupported)
    ));
    let material =
        ProjectOwnerKeyMaterial::from_backup_seed(reference.clone(), Zeroizing::new([7; 32]))
            .expect("material");
    assert_eq!(
        store.restore_active(None, material),
        Err(StoreStatus::Unsupported)
    );
    assert_eq!(
        store.reset_after_compromise(&reference, &floor),
        Err(StoreStatus::Unsupported)
    );
}

#[test]
fn public_types_reject_wrong_repository_zero_epoch_and_invalid_key_material() {
    assert_eq!(
        ProjectOwnerKeyRef::new("other", key_ref().public_key(), 1),
        Err(StoreStatus::Denied)
    );
    assert_eq!(
        ProjectOwnerKeyRef::new("gocode", key_ref().public_key(), 0),
        Err(StoreStatus::Denied)
    );
    assert!(matches!(
        ProjectOwnerAnchorFloor::new("gocode", 0, [8; 32]),
        Err(StoreStatus::Denied)
    ));
}

#[test]
fn backup_material_derives_its_public_reference_and_consumes_its_seed() {
    let reference = ProjectOwnerKeyRef::new(
        "gocode",
        SigningKey::from_bytes(&[7; 32]).verifying_key().to_bytes(),
        3,
    )
    .expect("reference");
    let material =
        ProjectOwnerKeyMaterial::from_backup_seed(reference.clone(), Zeroizing::new([7; 32]))
            .expect("material");
    assert_eq!(material.key_ref().key_epoch(), 3);
    assert_eq!(
        material.key_ref().public_key(),
        SigningKey::from_bytes(&[7; 32]).verifying_key().to_bytes()
    );
    assert_eq!(*material.into_backup_seed(), [7; 32]);
    assert!(matches!(
        ProjectOwnerKeyMaterial::from_backup_seed(reference, Zeroizing::new([8; 32])),
        Err(StoreStatus::Denied)
    ));
    assert_eq!(validate_transcript(b""), Err(StoreStatus::Denied));
    assert_eq!(
        validate_transcript(&vec![0; MAX_PROJECT_OWNER_TRANSCRIPT_BYTES + 1]),
        Err(StoreStatus::Denied)
    );
}

#[test]
fn backend_pending_spi_preserves_opaque_token_and_enforces_transcript_bound() {
    let reference = key_ref();
    let pending = PendingProjectOwnerKey::from_backend_generated(
        reference.clone(),
        [9; 64],
        Zeroizing::new([10; 32]),
        b"proof transcript",
    )
    .expect("bounded backend record");
    assert_eq!(pending.key_ref(), &reference);
    assert_eq!(pending.proof_of_possession(), [9; 64]);
    assert!(pending.matches_backend_token(&[10; 32]));
    assert!(!pending.matches_backend_token(&[11; 32]));
    let mut changed_first = [10; 32];
    changed_first[0] = 0;
    assert!(!pending.matches_backend_token(&changed_first));
    let mut changed_last = [10; 32];
    changed_last[31] = 0;
    assert!(!pending.matches_backend_token(&changed_last));
    assert!(matches!(
        PendingProjectOwnerKey::from_backend_generated(
            reference,
            [9; 64],
            Zeroizing::new([10; 32]),
            &vec![0; MAX_PROJECT_OWNER_TRANSCRIPT_BYTES + 1],
        ),
        Err(StoreStatus::Denied)
    ));
}

#[test]
fn secret_material_exposes_no_clone_debug_serde_or_generic_seed_getter() {
    let source = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/project_owner_key.rs"
    ))
    .expect("source");
    let material = source
        .split("pub struct ProjectOwnerKeyMaterial")
        .nth(1)
        .expect("material");
    let material = material
        .split("pub struct PendingProjectOwnerKey")
        .next()
        .expect("boundary");
    for forbidden in ["Clone", "Debug", "Serialize", "Deserialize", "fn seed("] {
        assert!(
            !material.contains(forbidden),
            "secret material leaked {forbidden}"
        );
    }
    assert!(material.contains("fn into_backup_seed(self)"));
}
