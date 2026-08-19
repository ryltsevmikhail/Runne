#![cfg(all(test, not(target_os = "macos")))]

use ed25519_dalek::SigningKey;
use std::cell::Cell;
use zeroize::Zeroizing;

use crate::{
    PendingProjectOwnerKey, ProjectOwnerAnchorFloor, ProjectOwnerKeyMaterial, ProjectOwnerKeyRef,
    ProjectOwnerKeyStore, StoreStatus, StubStore,
};

fn reference() -> ProjectOwnerKeyRef {
    ProjectOwnerKeyRef::new(
        "runne",
        SigningKey::from_bytes(&[7; 32]).verifying_key().to_bytes(),
        1,
    )
    .expect("reference")
}

#[test]
fn stub_rejects_all_operations_without_invoking_pending_callback() {
    let store = StubStore::new();
    let reference = reference();
    let floor = ProjectOwnerAnchorFloor::new("runne", 1, [8; 32]).expect("floor");
    let calls = Cell::new(0);
    let mut callback = |_key: &ProjectOwnerKeyRef| {
        calls.set(calls.get() + 1);
        Ok(Vec::from([1_u8]))
    };
    assert!(matches!(
        store.create_pending(None, "runne", 1, &mut callback),
        Err(StoreStatus::Unsupported)
    ));
    assert_eq!(calls.get(), 0);
    assert!(matches!(
        store.create_or_resume_pending(None, "runne", 1, &mut callback),
        Err(StoreStatus::Unsupported)
    ));
    assert_eq!(calls.get(), 0);
    assert_eq!(
        store.sign_active(&reference, b"transcript"),
        Err(StoreStatus::Unsupported)
    );
    let pending = PendingProjectOwnerKey::from_backend_generated(
        reference.clone(),
        [0; 64],
        Zeroizing::new([1; 32]),
        b"proof",
    )
    .expect("pending");
    assert_eq!(
        store.activate_pending(None, pending),
        Err(StoreStatus::Unsupported)
    );
    let pending = PendingProjectOwnerKey::from_backend_generated(
        reference.clone(),
        [0; 64],
        Zeroizing::new([1; 32]),
        b"proof",
    )
    .expect("pending");
    assert_eq!(
        store.commit_pending_and_floor(None, pending, None, &floor),
        Err(StoreStatus::Unsupported)
    );
    assert_eq!(
        store.read_active_ref("runne"),
        Err(StoreStatus::Unsupported)
    );
    assert_eq!(
        store.read_anchor_floor("runne"),
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
