#![cfg(unix)]

use std::fs;
use std::os::unix::fs::{PermissionsExt as _, symlink};
use std::sync::{Arc, Barrier};

use runne_daemon_loopback_fixture::{RetainedFixtureKeyring, prepare_runtime_root};
use runne_secure_store::{
    ProviderJournalKeyMaterial, ProviderJournalKeyRef, ProviderJournalKeyring,
};

const KEY_NAME: &str = "fixture-provider-journal-key.bin";

fn private_root() -> tempfile::TempDir {
    let root = tempfile::tempdir().expect("create synthetic root");
    fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700))
        .expect("make synthetic root owner-private");
    root
}

fn key_ref(marker: u8) -> ProviderJournalKeyRef {
    ProviderJournalKeyRef::new([marker; 16], u64::from(marker), [marker + 1; 16], 1)
        .expect("create synthetic key reference")
}

fn key_material(marker: u8) -> ProviderJournalKeyMaterial {
    ProviderJournalKeyMaterial::new(key_ref(marker), [marker; 32])
        .expect("create synthetic key material")
}

fn assert_store_rejects(root: &std::path::Path) {
    assert!(
        prepare_runtime_root(root).is_err(),
        "unsafe key must be rejected"
    );
}

#[test]
fn rejects_a_symlinked_runtime_root() {
    let parent = tempfile::tempdir().expect("create synthetic parent");
    let target = parent.path().join("target");
    fs::create_dir(&target).expect("create synthetic target");
    fs::set_permissions(&target, fs::Permissions::from_mode(0o700))
        .expect("make synthetic target owner-private");
    let root = parent.path().join("runtime");
    symlink(&target, &root).expect("create root symlink");

    assert!(
        prepare_runtime_root(&root).is_err(),
        "root symlink must be rejected"
    );
}

#[test]
fn rejects_a_key_symlink_without_changing_the_external_sentinel() {
    let root = private_root();
    let external = tempfile::NamedTempFile::new().expect("create synthetic sentinel");
    let sentinel = [0x5a; 80];
    fs::write(external.path(), sentinel).expect("write synthetic sentinel");
    symlink(external.path(), root.path().join(KEY_NAME)).expect("create key symlink");

    assert_store_rejects(root.path());
    assert_eq!(fs::read(external.path()).expect("read sentinel"), sentinel);
}

#[test]
fn replacement_over_a_key_symlink_never_modifies_its_target() {
    let root = private_root();
    let original = prepare_runtime_root(root.path()).expect("create synthetic key");
    let keyring = RetainedFixtureKeyring::open(root.path()).expect("hold root descriptor");
    let external = tempfile::NamedTempFile::new().expect("create synthetic sentinel");
    let sentinel = [0x4b; 80];
    fs::write(external.path(), sentinel).expect("write synthetic sentinel");
    fs::remove_file(original.path()).expect("replace fixture key with symlink");
    symlink(external.path(), original.path()).expect("create replacement symlink");
    let replacement = key_material(7);

    keyring
        .store_provider_journal_key(&replacement)
        .expect("replace fixture key through held descriptor");

    assert_eq!(fs::read(external.path()).expect("read sentinel"), sentinel);
    let stored = keyring
        .load_provider_journal_key(replacement.key_ref())
        .expect("load replaced synthetic key");
    assert_eq!(stored.key_ref(), replacement.key_ref());
    assert_eq!(stored.with_bytes(|bytes| *bytes), [7; 32]);
}

#[test]
fn rejects_wrong_mode_type_size_and_hardlink() {
    let root = private_root();
    let key = prepare_runtime_root(root.path()).expect("create synthetic key");

    fs::set_permissions(key.path(), fs::Permissions::from_mode(0o4600))
        .expect("set special synthetic mode");
    assert_store_rejects(root.path());

    fs::set_permissions(key.path(), fs::Permissions::from_mode(0o600))
        .expect("restore synthetic mode");
    fs::write(key.path(), [0x11; 79]).expect("write wrong synthetic size");
    assert_store_rejects(root.path());

    fs::write(key.path(), [0x12; 80]).expect("restore synthetic size");
    let sibling = root.path().join("synthetic-hardlink");
    fs::hard_link(key.path(), &sibling).expect("create synthetic hardlink");
    assert_store_rejects(root.path());
    fs::remove_file(sibling).expect("remove synthetic hardlink");

    fs::remove_file(key.path()).expect("remove synthetic key");
    fs::create_dir(key.path()).expect("create synthetic directory");
    assert_store_rejects(root.path());
}

#[test]
fn atomic_readers_observe_only_complete_old_or_new_records() {
    let root = private_root();
    let original = prepare_runtime_root(root.path()).expect("create synthetic key");
    let keyring =
        Arc::new(RetainedFixtureKeyring::open(root.path()).expect("hold root descriptor"));
    let replacement = key_material(9);
    let replacement_ref = replacement.key_ref();
    let barrier = Arc::new(Barrier::new(2));
    let writer_keyring = Arc::clone(&keyring);
    let writer_barrier = Arc::clone(&barrier);
    let writer = std::thread::spawn(move || {
        writer_barrier.wait();
        writer_keyring
            .store_provider_journal_key(&replacement)
            .expect("atomically replace synthetic key");
    });

    barrier.wait();
    for _ in 0..256 {
        let observed = prepare_runtime_root(root.path()).expect("read complete key record");
        assert!(
            (observed.key_ref() == original.key_ref() && observed.bytes() == original.bytes())
                || (observed.key_ref() == replacement_ref && observed.bytes() == [9; 32]),
            "reader must observe a complete old or new synthetic record"
        );
    }
    writer.join().expect("join key writer");
    let final_key = prepare_runtime_root(root.path()).expect("read replacement key");
    assert_eq!(final_key.key_ref(), replacement_ref);
    assert_eq!(final_key.bytes(), [9; 32]);
}

#[test]
fn restart_uses_the_exact_synthetic_reference_and_bytes_with_mode_0600() {
    let root = private_root();
    let keyring = RetainedFixtureKeyring::open(root.path()).expect("hold root descriptor");
    let expected = key_material(13);
    let expected_ref = expected.key_ref();
    keyring
        .store_provider_journal_key(&expected)
        .expect("store synthetic key");
    drop(keyring);

    let second_process = RetainedFixtureKeyring::open(root.path()).expect("reopen root descriptor");
    let restored = second_process
        .load_provider_journal_key(expected_ref)
        .expect("load exact synthetic key");
    assert_eq!(restored.key_ref(), expected_ref);
    assert_eq!(restored.with_bytes(|bytes| *bytes), [13; 32]);
    assert_eq!(
        fs::metadata(root.path().join(KEY_NAME))
            .expect("read key metadata")
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
}
