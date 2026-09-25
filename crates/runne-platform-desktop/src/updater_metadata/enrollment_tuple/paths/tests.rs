use super::*;

fn macos_layout(directory: &Path) -> [PathBuf; 4] {
    let contents = directory.join("Runne.app/Contents");
    let macos = contents.join("MacOS");
    let contract = contents.join("Resources/contracts/gocode-ui-client-3/bundle.json");
    std::fs::create_dir_all(contract.parent().unwrap()).unwrap();
    std::fs::create_dir_all(&macos).unwrap();
    let paths = [
        macos.join("runne-desktop"),
        macos.join("runne"),
        macos.join("runned"),
        contract,
    ];
    for path in &paths {
        std::fs::write(path, path.file_name().unwrap().as_encoded_bytes()).unwrap();
    }
    paths
}

#[test]
fn paths_reject_a_layout_outside_the_macos_application_bundle() {
    let directory = tempfile::tempdir().unwrap();
    let paths = ["desktop", "writer", "daemon", "contract"].map(|name| directory.path().join(name));
    assert!(
        NativeEnrollmentArtifactPathsV1::new(&paths[0], &paths[1], &paths[2], &paths[3]).is_err()
    );
}

#[test]
fn paths_accept_only_the_exact_macos_application_layout() {
    let directory = tempfile::tempdir().unwrap();
    let paths = macos_layout(directory.path());
    // Admission of the bundle layout is the descriptor-rooted unix production
    // path; non-unix desktops reject every layout in production (covered by
    // the swap and outside-bundle assertions below).
    #[cfg(unix)]
    assert!(
        NativeEnrollmentArtifactPathsV1::new(&paths[0], &paths[1], &paths[2], &paths[3]).is_ok()
    );
    assert!(
        NativeEnrollmentArtifactPathsV1::new(&paths[0], &paths[2], &paths[1], &paths[3]).is_err()
    );
}

#[cfg(unix)]
#[test]
fn paths_reject_symlinked_role_and_ancestor() {
    use std::os::unix::fs::symlink;
    let directory = tempfile::tempdir().unwrap();
    let paths = macos_layout(directory.path());
    std::fs::remove_file(&paths[1]).unwrap();
    symlink(&paths[2], &paths[1]).unwrap();
    assert!(
        NativeEnrollmentArtifactPathsV1::new(&paths[0], &paths[1], &paths[2], &paths[3]).is_err()
    );
    let paths = macos_layout(directory.path().join("second").as_path());
    let contents = directory.path().join("second/Runne.app/Contents");
    let replacement = directory.path().join("second/Runne.app/RealContents");
    std::fs::rename(&contents, &replacement).unwrap();
    symlink(&replacement, &contents).unwrap();
    assert!(
        NativeEnrollmentArtifactPathsV1::new(&paths[0], &paths[1], &paths[2], &paths[3]).is_err()
    );
}

#[cfg(unix)]
#[test]
fn captured_paths_reject_same_size_replacement_and_late_hardlink() {
    let directory = tempfile::tempdir().unwrap();
    let paths = macos_layout(directory.path());
    let captured =
        NativeEnrollmentArtifactPathsV1::new(&paths[0], &paths[1], &paths[2], &paths[3]).unwrap();
    let replacement = paths[1].with_extension("replacement");
    std::fs::write(&replacement, b"replacement").unwrap();
    std::fs::rename(replacement, &paths[1]).unwrap();
    assert!(captured.measure().is_err());
    let paths = macos_layout(directory.path().join("second").as_path());
    let captured =
        NativeEnrollmentArtifactPathsV1::new(&paths[0], &paths[1], &paths[2], &paths[3]).unwrap();
    std::fs::hard_link(&paths[1], paths[1].with_extension("link")).unwrap();
    assert!(captured.measure().is_err());
}

// In-place mutation detection relies on the captured descriptor observing the
// writer's mtime/ctime update; overlay filesystems (Linux CI containers) keep
// the opened descriptor on the lower layer, so this holds on APFS only.
#[cfg(target_os = "macos")]
#[test]
fn captured_paths_reject_same_size_in_place_mutation() {
    let directory = tempfile::tempdir().unwrap();
    let paths = macos_layout(directory.path());
    let captured =
        NativeEnrollmentArtifactPathsV1::new(&paths[0], &paths[1], &paths[2], &paths[3]).unwrap();
    std::fs::write(&paths[1], b"other").unwrap();
    assert!(captured.measure().is_err());
}

// Same-size substitution is detected through the captured descriptor's stat
// snapshot; see the in-place mutation note about overlay filesystems.
#[cfg(target_os = "macos")]
#[test]
fn captured_paths_reject_daemon_or_contract_substitution() {
    for index in [2, 3] {
        let directory = tempfile::tempdir().unwrap();
        let paths = macos_layout(directory.path());
        let captured =
            NativeEnrollmentArtifactPathsV1::new(&paths[0], &paths[1], &paths[2], &paths[3])
                .unwrap();
        std::fs::write(&paths[index], b"substituted").unwrap();

        assert!(captured.measure().is_err());
    }
}

#[cfg(unix)]
#[test]
fn final_confirmation_rejects_replacement_after_measurement() {
    let directory = tempfile::tempdir().unwrap();
    let paths = macos_layout(directory.path());
    let captured =
        NativeEnrollmentArtifactPathsV1::new(&paths[0], &paths[1], &paths[2], &paths[3]).unwrap();
    assert!(captured.measure().is_ok());
    let replacement = paths[1].with_extension("post-measurement");
    std::fs::write(&replacement, b"replacement").unwrap();
    std::fs::rename(replacement, &paths[1]).unwrap();
    assert!(captured.confirm_current().is_err());
}

#[cfg(target_os = "macos")]
#[test]
fn daemon_confirmation_rejects_a_digest_not_measured_from_the_retained_descriptor() {
    let directory = tempfile::tempdir().unwrap();
    let paths = macos_layout(directory.path());
    let captured =
        NativeEnrollmentArtifactPathsV1::new(&paths[0], &paths[1], &paths[2], &paths[3]).unwrap();

    assert!(captured.confirm_current_daemon([0; 32]).is_err());
}
