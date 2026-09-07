use std::fs::{self, OpenOptions};
use std::io::Write as _;
use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _, symlink};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};

use super::layout::{ENTRIES, application_from_service, rooted_path};
use super::package::ServicePackage;

static NEXT_DIRECTORY: AtomicUsize = AtomicUsize::new(0);

#[test]
fn credential_service_observation_pure_locator_requires_the_exact_nested_suffix() {
    let exact = Path::new(
        "/Applications/Runne.app/Contents/Library/Helpers/RunneCredentialService.app/Contents/MacOS/runne-credential-service",
    );
    assert_eq!(
        application_from_service(exact).unwrap(),
        Path::new("/Applications/Runne.app")
    );
    for invalid in [
        Path::new(
            "Runne.app/Contents/Library/Helpers/RunneCredentialService.app/Contents/MacOS/runne-credential-service",
        ),
        Path::new(
            "/Applications/Runne.app/Contents/Library/Helpers/Other.app/Contents/MacOS/runne-credential-service",
        ),
        Path::new(
            "/Applications/Runne.app/Contents/Library/Helpers/RunneCredentialService.app/Contents/MacOS/other",
        ),
        Path::new(
            "/Applications/Runne.app/Contents/Library/Helpers/RunneCredentialService.app/Contents/MacOS/runne-credential-service/extra",
        ),
    ] {
        assert!(
            application_from_service(invalid).is_err(),
            "accepted {invalid:?}"
        );
    }
}

#[test]
fn credential_service_observation_pure_retains_and_revalidates_all_ten_entries() {
    for (index, entry) in ENTRIES.into_iter().enumerate() {
        let root = fixture_root(&format!("retained-{index}"));
        let package = ServicePackage::capture(&root).expect("capture all ten rooted entries");
        package.revalidate().expect("unchanged package");
        let path = rooted_path(&root, entry);
        OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap()
            .write_all(b"x")
            .unwrap();
        assert!(
            package.revalidate().is_err(),
            "mutation accepted for {path:?}"
        );
        fs::remove_dir_all(root.parent().unwrap()).unwrap();
    }
}

#[test]
fn credential_service_observation_pure_rejects_unsafe_links_modes_and_candidate_bounds() {
    let root = fixture_root("symlink");
    let candidate = rooted_path(&root, ENTRIES[0]);
    fs::remove_file(&candidate).unwrap();
    symlink("/etc/passwd", &candidate).unwrap();
    assert!(ServicePackage::capture(&root).is_err());
    fs::remove_dir_all(root.parent().unwrap()).unwrap();

    let root = fixture_root("mode");
    fs::set_permissions(
        rooted_path(&root, ENTRIES[5]),
        fs::Permissions::from_mode(0o666),
    )
    .unwrap();
    assert!(ServicePackage::capture(&root).is_err());
    fs::remove_dir_all(root.parent().unwrap()).unwrap();

    let root = fixture_root("candidate-bound");
    let candidate = rooted_path(&root, ENTRIES[0]);
    fs::write(&candidate, vec![b'a'; 64 * 1024 + 1]).unwrap();
    assert!(ServicePackage::capture(&root).is_err());
    fs::remove_dir_all(root.parent().unwrap()).unwrap();

    let root = fixture_root("resource-bound");
    let launch_agent = rooted_path(&root, ENTRIES[5]);
    fs::write(&launch_agent, vec![b'a'; 64 * 1024 + 1]).unwrap();
    assert!(ServicePackage::capture(&root).is_err());
    fs::remove_dir_all(root.parent().unwrap()).unwrap();
}

#[test]
fn credential_service_observation_pure_projects_candidate_from_its_embedded_digest() {
    let root = fixture_root("candidate-projection");
    let candidate = rooted_path(&root, ENTRIES[0]);
    fs::write(&candidate, candidate_binding("a")).unwrap();
    let package = ServicePackage::capture(&root).unwrap();
    let projection = package
        .release_digests(&package.candidate_binding().unwrap())
        .unwrap();
    assert_eq!(projection.candidate_sha256, "a".repeat(64));
    fs::write(&candidate, candidate_binding("b")).unwrap();
    assert!(
        package.revalidate().is_err(),
        "candidate file replacement accepted"
    );
    fs::remove_dir_all(root.parent().unwrap()).unwrap();
}

fn fixture_root(label: &str) -> PathBuf {
    let sequence = NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed);
    let base = PathBuf::from("/private/tmp").join(format!(
        "runne-credential-service-{label}-{}-{sequence}",
        std::process::id()
    ));
    let root = base.join("Runne.app");
    for (index, entry) in ENTRIES.into_iter().enumerate() {
        let path = rooted_path(&root, entry);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::set_permissions(path.parent().unwrap(), fs::Permissions::from_mode(0o700)).unwrap();
        let mode = if (1..=4).contains(&index) {
            0o700
        } else {
            0o600
        };
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(mode)
            .open(path)
            .unwrap();
        file.write_all(format!("entry-{index}").as_bytes()).unwrap();
    }
    root
}

fn candidate_binding(digest: &str) -> String {
    format!(
        "{{\"schemaVersion\":1,\"productId\":\"runne\",\"version\":\"1.0.0\",\"platform\":\"macos\",\"arch\":\"arm64\",\"profileId\":\"protected-bundled\",\"releaseCandidateSha256\":\"{}\"}}",
        digest.repeat(64)
    )
}
