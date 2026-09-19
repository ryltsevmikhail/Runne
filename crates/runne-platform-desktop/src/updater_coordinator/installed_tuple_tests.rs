#[test]
fn committed_installed_tuple_survives_coordinator_restart() {
    let directory = tempfile::tempdir().unwrap();
    let initial = coordinator(directory.path());
    record(&initial, directory.path());
    initial
        .trust_journal
        .initialize("1.0.0", "1.0.0")
        .unwrap();
    initial.prepare_restart(0, false).unwrap();
    initial.begin_health_check().unwrap();
    initial.complete_health(true, "1.2.0").unwrap();

    let restarted = coordinator(directory.path());
    assert!(restarted
        .admit_installed_native_enrollment_at(100, &artifacts())
        .unwrap()
        .is_some());
}

#[test]
fn installed_tuple_admission_rejects_non_current_or_substituted_artifacts() {
    let directory = tempfile::tempdir().unwrap();
    let coordinator = coordinator(directory.path());
    record(&coordinator, directory.path());
    coordinator
        .trust_journal
        .initialize("1.0.0", "1.0.0")
        .unwrap();
    coordinator.prepare_restart(0, false).unwrap();
    coordinator.begin_health_check().unwrap();
    coordinator.complete_health(true, "1.2.0").unwrap();

    assert!(coordinator
        .admit_installed_native_enrollment_at(500, &artifacts())
        .is_err());
    coordinator.trust_journal.commit_install("1.2.1").unwrap();
    assert!(coordinator
        .admit_installed_native_enrollment_at(100, &artifacts())
        .unwrap()
        .is_none());
    let substituted = MeasuredNativeEnrollmentArtifactsV1::test_only_from_digests(
        "c".repeat(64),
        "f".repeat(64),
        "e".repeat(64),
        "a".repeat(64),
    )
    .unwrap();
    assert!(coordinator
        .admit_installed_native_enrollment_at(100, &substituted)
        .unwrap()
        .is_none());
}

// The retained-paths fixture requires the unix-only macOS-bundle admission;
// the expiry/trust contract itself keeps cross-platform coverage through the
// digest-based admission and revalidation tests in this file.
#[cfg(unix)]
#[test]
fn prepared_enrollment_refresh_rejects_expiry_and_advanced_trust() {
    let directory = tempfile::tempdir().unwrap();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let (coordinator, artifacts, verified) = native_fixture(directory.path(), now + 60, "f".repeat(64));
    let prepared = retained_prepared(directory.path(), &verified, &artifacts);
    assert!(coordinator
        .refresh_installed_native_enrollment_at(prepared, now + 61)
        .is_err());

    coordinator.trust_journal.commit_install("1.2.1").unwrap();
    let prepared = retained_prepared(directory.path(), &verified, &artifacts);
    assert!(coordinator
        .refresh_installed_native_enrollment_at(prepared, now)
        .unwrap()
        .is_none());
}

#[test]
fn confirmed_enrollment_revalidation_is_atomic_against_expiry_and_trust() {
    let directory = tempfile::tempdir().unwrap();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let (coordinator, artifacts, verified) = native_fixture(directory.path(), now + 60, "f".repeat(64));
    let confirmed = crate::ConfirmedInstalledNativeEnrollment::test_only_from_admission(
        verified.admit_native_enrollment(&artifacts).unwrap(),
    );
    assert!(coordinator
        .test_only_revalidate_confirmed_native_enrollment_at(&confirmed, now, &artifacts)
        .unwrap());
    assert!(coordinator
        .test_only_revalidate_confirmed_native_enrollment_at(&confirmed, now + 61, &artifacts)
        .is_err());

    coordinator.trust_journal.commit_install("1.2.1").unwrap();
    assert!(!coordinator
        .test_only_revalidate_confirmed_native_enrollment_at(&confirmed, now, &artifacts)
        .unwrap());
}

#[cfg(unix)]
fn retained_prepared(
    directory: &std::path::Path,
    verified: &crate::VerifiedUpdateV2,
    artifacts: &MeasuredNativeEnrollmentArtifactsV1,
) -> crate::PreparedInstalledNativeEnrollment {
    let macos = directory.join("refresh/Runne.app/Contents/MacOS");
    let contract = directory.join("refresh/Runne.app/Contents/Resources/contracts/gocode-ui-client-2/bundle.json");
    std::fs::create_dir_all(contract.parent().unwrap()).unwrap();
    std::fs::create_dir_all(&macos).unwrap();
    let paths = [macos.join("runne-desktop"), macos.join("runne"), macos.join("runned"), contract];
    for (path, bytes) in paths
        .iter()
        .zip([b"desktop".as_slice(), b"writer", b"daemon", b"contract"])
    {
        std::fs::write(path, bytes).unwrap();
    }
    let retained = crate::updater_metadata::NativeEnrollmentArtifactPathsV1::new(
        &paths[0], &paths[1], &paths[2], &paths[3],
    ).unwrap();
    verified.admit_native_enrollment(artifacts).unwrap().retain_installed_paths(retained)
}

fn metadata_path(directory: &std::path::Path) -> std::path::PathBuf {
    directory
        .join("updates")
        .join("installed-metadata.json.1.json")
}

fn committed_coordinator(directory: &std::path::Path) -> UpdateCoordinator {
    let coordinator = coordinator(directory);
    record(&coordinator, directory);
    coordinator
        .trust_journal
        .initialize("1.0.0", "1.0.0")
        .unwrap();
    coordinator.prepare_restart(0, false).unwrap();
    coordinator.begin_health_check().unwrap();
    coordinator.complete_health(true, "1.2.0").unwrap();
    coordinator
}

#[test]
fn restart_transition_requires_durable_signed_metadata() {
    let directory = tempfile::tempdir().unwrap();
    let coordinator = coordinator(directory.path());
    record(&coordinator, directory.path());
    std::fs::remove_file(metadata_path(directory.path())).unwrap();

    assert!(coordinator.prepare_restart(0, false).is_err());
}

#[test]
fn installed_tuple_admission_rejects_strict_or_signature_corruption() {
    let directory = tempfile::tempdir().unwrap();
    let coordinator = committed_coordinator(directory.path());
    let path = metadata_path(directory.path());
    let mut value: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    value
        .as_object_mut()
        .unwrap()
        .insert("unexpected".into(), serde_json::Value::Null);
    std::fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();
    assert!(coordinator
        .admit_installed_native_enrollment_at(100, &artifacts())
        .is_err());

    let directory = tempfile::tempdir().unwrap();
    let coordinator = committed_coordinator(directory.path());
    let path = metadata_path(directory.path());
    let mut value: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    value["targets"]["target"]["version"] = serde_json::Value::String("1.2.1".into());
    std::fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();
    assert!(coordinator
        .admit_installed_native_enrollment_at(100, &artifacts())
        .unwrap()
        .is_none());
}

#[test]
fn installed_tuple_admission_rejects_uncommitted_and_rolled_back_updates() {
    let directory = tempfile::tempdir().unwrap();
    let coordinator = coordinator(directory.path());
    record(&coordinator, directory.path());
    assert!(coordinator
        .admit_installed_native_enrollment_at(100, &artifacts())
        .unwrap()
        .is_none());
    coordinator.prepare_restart(0, false).unwrap();
    coordinator.begin_health_check().unwrap();
    coordinator.complete_health(false, "1.2.0").unwrap();
    assert!(coordinator
        .admit_installed_native_enrollment_at(100, &artifacts())
        .unwrap()
        .is_none());
}

#[test]
fn installed_admission_does_not_qualify_enrollment() {
    assert_eq!(
        verified_update().qualify_native_enrollment(&artifacts()),
        crate::NativeEnrollmentQualification::Unqualified
    );
}

#[test]
fn installed_tuple_admission_rejects_metadata_below_the_native_trust_floor() {
    let directory = tempfile::tempdir().unwrap();
    let coordinator = committed_coordinator(directory.path());
    coordinator
        .trust_journal
        .accept_metadata(8, 10, "1.2.0")
        .unwrap();

    assert!(coordinator
        .admit_installed_native_enrollment_at(100, &artifacts())
        .unwrap()
        .is_none());
}
