use std::fs;
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};

use super::FreshQualificationRunRoot;

const RUN: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const JOURNALS: [&str; 3] = [
    "install-state.json.2.json",
    "trust-state.json.2.json",
    "installed-metadata.json.2.json",
];

fn fixture() -> (tempfile::TempDir, PathBuf) {
    let temporary = tempfile::tempdir().unwrap();
    let profile = temporary.path().join("com.runne.desktop/bundled-runtime");
    fs::create_dir_all(updates(&profile)).unwrap();
    for name in JOURNALS {
        fs::write(updates(&profile).join(name), name).unwrap();
    }
    (temporary, fs::canonicalize(profile).unwrap())
}

fn updates(profile: &Path) -> PathBuf {
    profile.join("updates")
}

#[test]
fn fresh_root_copies_latest_journals_and_revalidates() {
    let (_temporary, profile) = fixture();
    fs::write(updates(&profile).join("install-state.json.1.json"), b"old").unwrap();
    fs::write(
        updates(&profile).join("activation-state.json.9.json"),
        b"secret",
    )
    .unwrap();
    let root = FreshQualificationRunRoot::create(&profile, RUN).unwrap();
    assert!(root.revalidate().is_some());
    for name in JOURNALS {
        assert_eq!(
            fs::read(root.path().join("updates").join(name)).unwrap(),
            name.as_bytes()
        );
    }
    assert!(
        !root
            .path()
            .join("updates/activation-state.json.9.json")
            .exists()
    );
}

#[test]
fn existing_root_missing_and_bad_names_are_rejected() {
    let (_temporary, profile) = fixture();
    assert!(FreshQualificationRunRoot::create(&profile, RUN).is_some());
    assert!(FreshQualificationRunRoot::create(&profile, RUN).is_none());
    assert!(FreshQualificationRunRoot::create(&profile, "not-a-directory-name").is_none());
    let (_temporary, profile) = fixture();
    fs::remove_file(updates(&profile).join(JOURNALS[1])).unwrap();
    assert!(FreshQualificationRunRoot::create(&profile, RUN).is_none());
    let (_temporary, profile) = fixture();
    fs::write(
        updates(&profile).join("trust-state.json.3.json.tmp"),
        b"bad",
    )
    .unwrap();
    assert!(FreshQualificationRunRoot::create(&profile, RUN).is_none());
}

#[test]
fn link_and_oversized_source_journals_are_rejected() {
    let (_temporary, profile) = fixture();
    let install = updates(&profile).join(JOURNALS[0]);
    fs::remove_file(&install).unwrap();
    std::os::unix::fs::symlink("missing", &install).unwrap();
    assert!(FreshQualificationRunRoot::create(&profile, RUN).is_none());
    let (_temporary, profile) = fixture();
    let install = updates(&profile).join(JOURNALS[0]);
    fs::write(&install, b"content").unwrap();
    fs::hard_link(&install, updates(&profile).join("copy")).unwrap();
    assert!(FreshQualificationRunRoot::create(&profile, RUN).is_none());
    let (_temporary, profile) = fixture();
    let install = updates(&profile).join(JOURNALS[0]);
    fs::File::create(&install)
        .unwrap()
        .set_len(16 * 1024 + 1)
        .unwrap();
    assert!(FreshQualificationRunRoot::create(&profile, RUN).is_none());
}

#[test]
fn source_and_destination_replacement_fail_revalidation() {
    let (_temporary, profile) = fixture();
    let root = FreshQualificationRunRoot::create(&profile, RUN).unwrap();
    fs::remove_file(updates(&profile).join(JOURNALS[0])).unwrap();
    fs::write(updates(&profile).join(JOURNALS[0]), b"replacement").unwrap();
    assert!(root.revalidate().is_none());
    let (_temporary, profile) = fixture();
    let root = FreshQualificationRunRoot::create(&profile, RUN).unwrap();
    fs::remove_file(root.path().join("updates").join(JOURNALS[0])).unwrap();
    fs::write(
        root.path().join("updates").join(JOURNALS[0]),
        b"replacement",
    )
    .unwrap();
    assert!(root.revalidate().is_none());
}

#[test]
fn injected_root_file_and_insecure_existing_base_are_rejected() {
    let (_temporary, profile) = fixture();
    let root = FreshQualificationRunRoot::create(&profile, RUN).unwrap();
    fs::write(root.path().join("ledger.sqlite3"), b"injected").unwrap();
    assert!(root.revalidate().is_none());
    let (_temporary, profile) = fixture();
    let base = profile.parent().unwrap().join("qualification-runs");
    fs::create_dir(&base).unwrap();
    fs::set_permissions(&base, fs::Permissions::from_mode(0o755)).unwrap();
    assert!(FreshQualificationRunRoot::create(&profile, RUN).is_none());
}

#[test]
fn latest_generation_and_root_directory_replacement_invalidate_preparation() {
    let (_temporary, profile) = fixture();
    let root = FreshQualificationRunRoot::create(&profile, RUN).unwrap();
    fs::write(updates(&profile).join("install-state.json.3.json"), b"new").unwrap();
    assert!(root.revalidate().is_none());

    let (_temporary, profile) = fixture();
    let root = FreshQualificationRunRoot::create(&profile, RUN).unwrap();
    let moved = root.path().with_file_name("moved-root");
    fs::rename(root.path(), &moved).unwrap();
    fs::create_dir(root.path()).unwrap();
    assert!(root.revalidate().is_none());
}

#[test]
fn symlinked_base_and_world_writable_source_are_rejected() {
    let (_temporary, profile) = fixture();
    let base = profile.parent().unwrap().join("qualification-runs");
    std::os::unix::fs::symlink(&profile, base).unwrap();
    assert!(FreshQualificationRunRoot::create(&profile, RUN).is_none());

    let (_temporary, profile) = fixture();
    fs::set_permissions(
        updates(&profile).join(JOURNALS[0]),
        fs::Permissions::from_mode(0o666),
    )
    .unwrap();
    assert!(FreshQualificationRunRoot::create(&profile, RUN).is_none());
}

#[test]
fn concurrent_attempts_have_exactly_one_fresh_root_winner() {
    let (_temporary, profile) = fixture();
    let start = std::sync::Arc::new(std::sync::Barrier::new(2));
    let mut handles = Vec::new();
    for _ in 0..2 {
        let profile = profile.clone();
        let start = start.clone();
        handles.push(std::thread::spawn(move || {
            start.wait();
            FreshQualificationRunRoot::create(&profile, RUN)
        }));
    }
    let winners = handles
        .into_iter()
        .filter_map(|handle| handle.join().unwrap())
        .collect::<Vec<_>>();
    assert_eq!(winners.len(), 1);
    assert!(winners[0].revalidate().is_some());
}
