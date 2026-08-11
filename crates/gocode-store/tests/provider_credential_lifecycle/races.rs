use std::sync::{Arc, Barrier};

use gocode_provider::{CredentialVersionState, ProviderCredentialVersionStore};

use super::support::*;

#[test]
fn one_compare_and_set_active_winner() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("active-cas.sqlite");
    let first = version(1);
    let second = version(2);
    let setup = store(&path);
    prepare(&setup, first.clone());
    prepare(&setup, second.clone());
    drop(setup);

    let barrier = Arc::new(Barrier::new(3));
    let handles = [(first, OWNER_A, 21), (second, OWNER_B, 22)].map(|(reference, owner, fence)| {
        let path = path.clone();
        let barrier = Arc::clone(&barrier);
        std::thread::spawn(move || {
            let store = store(&path);
            barrier.wait();
            store.activate(lease(reference, owner, 500, fence))
        })
    });
    barrier.wait();
    let winners = handles
        .into_iter()
        .map(|handle| handle.join().unwrap())
        .filter(Result::is_ok)
        .count();

    assert_eq!(winners, 1);
    assert_eq!(store(&path).active_version_count("openai").unwrap(), 1);
}

#[test]
fn rotation_revoke_gc_race_has_one_terminal_owner() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("rotation-race.sqlite");
    let first = version(1);
    let second = version(2);
    let setup = store(&path);
    prepare(&setup, first.clone());
    prepare(&setup, second.clone());
    setup
        .activate(lease(first.clone(), OWNER_A, 500, 31))
        .unwrap();
    drop(setup);

    let (lifecycle, native) = store_with_native(&path);
    let store = Arc::new(lifecycle);
    let native = Arc::new(native);
    native.create(first.clone(), b"fixture-credential-value");
    let barrier = Arc::new(Barrier::new(3));
    let handles = (0..2)
        .map(|_| {
            let store = Arc::clone(&store);
            let native = Arc::clone(&native);
            let barrier = Arc::clone(&barrier);
            std::thread::spawn(move || {
                barrier.wait();
                let _ = store.revoke_and_fence(
                    gocode_provider::RevokeCredentialVersion::new(version(1), 31).unwrap(),
                );
                finish_deletions(&store, &native, 100)
            })
        })
        .collect::<Vec<_>>();
    barrier.wait();
    for handle in handles {
        handle.join().unwrap().unwrap();
    }

    assert_eq!(
        store.version_state(&first).unwrap(),
        CredentialVersionState::Deleted
    );
    assert_eq!(native.delete_calls(&first), 1);
    store
        .activate(lease(second.clone(), OWNER_B, 900, 32))
        .unwrap();
    assert_eq!(
        store.version_state(&second).unwrap(),
        CredentialVersionState::Active
    );
    assert_eq!(store.active_version_count("openai").unwrap(), 1);
}
