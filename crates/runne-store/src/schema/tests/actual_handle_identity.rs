#[cfg(unix)]
fn identity_fixture(name: &str) -> (tempfile::TempDir, PathBuf) {
    let root = tempfile::Builder::new().prefix(name).tempdir().unwrap();
    let daemon = root.path().join("runne-daemon");
    fs::create_dir(&daemon).unwrap();
    fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
    fs::set_permissions(&daemon, fs::Permissions::from_mode(0o700)).unwrap();
    (root, daemon.join("event-log.sqlite"))
}

#[cfg(unix)]
fn initialized_database(path: &Path) {
    let connection = open_managed_connection(path, ConnectionMode::Writer).unwrap();
    apply_migrations(&connection).unwrap();
}

#[cfg(unix)]
fn replacement_database(path: &Path) -> PathBuf {
    let replacement = path.with_extension("replacement");
    initialized_database(&replacement);
    replacement
}

#[cfg(unix)]
fn aba_swap(stage: IdentityHookStage, path: &Path, replacement: &Path) {
    let retained = path.with_extension("retained");
    let opened = path.with_extension("opened");
    match stage {
        IdentityHookStage::Retained => {
            fs::rename(path, retained).unwrap();
            fs::rename(replacement, path).unwrap();
        }
        IdentityHookStage::Opened => {
            fs::rename(path, opened).unwrap();
            fs::rename(retained, path).unwrap();
        }
        IdentityHookStage::Classified => {}
    }
}

#[cfg(unix)]
#[test]
fn ordinary_existing_open_rejects_actual_handle_aba() {
    let (_root, path) = identity_fixture("ordinary-aba");
    initialized_database(&path);
    let replacement = replacement_database(&path);
    let result = open_connection_for_profile_with_hook(&path, ConnectionMode::Writer, |stage| {
        aba_swap(stage, &path, &replacement);
        Ok(())
    });
    assert!(result.is_err());
}

#[cfg(unix)]
#[test]
fn new_file_open_rejects_create_drop_reopen_aba() {
    let (_root, path) = identity_fixture("new-file-aba");
    let replacement = replacement_database(&path);
    let result = open_connection_for_profile_with_hook(&path, ConnectionMode::Writer, |stage| {
        aba_swap(stage, &path, &replacement);
        Ok(())
    });
    assert!(result.is_err());
}

#[cfg(unix)]
#[test]
fn immutable_classification_rejects_actual_handle_aba() {
    let (_root, path) = identity_fixture("immutable-aba");
    initialized_database(&path);
    let replacement = replacement_database(&path);
    let result = open_classified_immutable_read_only_with_hook(&path, |stage| {
        aba_swap(stage, &path, &replacement);
        Ok(())
    });
    assert!(result.is_err());
}

#[cfg(unix)]
#[test]
fn validated_reopen_rejects_actual_handle_aba() {
    let (_root, path) = identity_fixture("validated-aba");
    initialized_database(&path);
    let replacement = replacement_database(&path);
    let result = reopen_managed_connection_validated_with_hook(
        &path,
        ConnectionMode::ValidatedReopen,
        |stage| {
            aba_swap(stage, &path, &replacement);
            Ok(())
        },
        |_| Ok(()),
    );
    assert!(result.is_err());
}

#[cfg(unix)]
#[test]
fn hot_reader_rejects_one_way_main_file_replacement() {
    let (_root, path) = identity_fixture("hot-reader-replacement");
    let writer = open_managed_connection(&path, ConnectionMode::Writer).unwrap();
    apply_migrations(&writer).unwrap();
    writer.execute_batch("BEGIN IMMEDIATE; COMMIT;").unwrap();
    for candidate in [&path, &sidecar_path(&path, "-wal"), &sidecar_path(&path, "-shm")] {
        if candidate.exists() {
            fs::set_permissions(candidate, fs::Permissions::from_mode(0o600)).unwrap();
        }
    }
    let replacement = replacement_database(&path);
    let retained = path.with_extension("retained");
    let result = open_connection_for_profile_with_hook(&path, ConnectionMode::Reader, |stage| {
        if matches!(stage, IdentityHookStage::Retained) {
            fs::rename(&path, &retained).unwrap();
            fs::rename(&replacement, &path).unwrap();
        }
        Ok(())
    });
    assert!(result.is_err());
}

#[cfg(unix)]
#[test]
fn validated_reopen_rejects_wal_handle_aba_before_writes() {
    let (_root, path) = identity_fixture("validated-wal-aba");
    let writer = open_managed_connection(&path, ConnectionMode::Writer).unwrap();
    apply_migrations(&writer).unwrap();
    writer.execute_batch("BEGIN IMMEDIATE; COMMIT;").unwrap();
    let wal = sidecar_path(&path, "-wal");
    let retained = path.with_extension("retained-wal");
    let opened = path.with_extension("opened-wal");
    for candidate in [&path, &wal, &sidecar_path(&path, "-shm")] {
        fs::set_permissions(candidate, fs::Permissions::from_mode(0o600)).unwrap();
    }
    let result = reopen_managed_connection_validated_with_hook(
        &path,
        ConnectionMode::ValidatedReopen,
        |stage| {
            match stage {
                IdentityHookStage::Retained => {
                    fs::rename(&wal, &retained).unwrap();
                    fs::copy(&retained, &wal).unwrap();
                    fs::set_permissions(&wal, fs::Permissions::from_mode(0o600)).unwrap();
                }
                IdentityHookStage::Opened => {}
                IdentityHookStage::Classified => {
                    fs::rename(&wal, &opened).unwrap();
                    fs::rename(&retained, &wal).unwrap();
                }
            }
            Ok(())
        },
        |_| Ok(()),
    );
    assert!(result.is_err());
}

#[cfg(unix)]
#[test]
fn scanner_sidecar_reopen_rejects_actual_handle_aba() {
    let (_root, base) = identity_fixture("scanner-sidecar-aba");
    let replacement_base = base.with_extension("other-base");
    drop(
        crate::provider::SqliteProviderRecoveryStore::open(&base, [1; 16]).unwrap(),
    );
    drop(
        crate::provider::SqliteProviderRecoveryStore::open(&replacement_base, [1; 16]).unwrap(),
    );
    let path = PathBuf::from(format!("{}.scanner-recovery", base.display()));
    let replacement = PathBuf::from(format!(
        "{}.scanner-recovery",
        replacement_base.display()
    ));
    let result = reopen_managed_scanner_sidecar_with_hook(&path, [1; 16], |stage| {
        aba_swap(stage, &path, &replacement);
        Ok(())
    });
    assert!(result.is_err());
}
