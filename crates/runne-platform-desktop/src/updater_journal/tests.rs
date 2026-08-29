use super::*;

fn staged(directory: &std::path::Path) -> super::super::StagedUpdate {
    super::super::StagedUpdate {
        path: directory.join("staged.update"),
        artifact_sha256: "a".repeat(64),
    }
}

#[test]
fn orphan_temp_allocates_a_new_sequence_without_replacing_final() {
    let directory = tempfile::tempdir().unwrap();
    let journal = UpdateJournal::new(directory.path().join("install-state.json"));
    journal
        .record_staged_bound("1.2.3", &staged(directory.path()), "b".repeat(64))
        .unwrap();
    std::fs::write(
        super::journal_wire::numbered_path(&journal.path, 2, "tmp"),
        b"partial",
    )
    .unwrap();
    journal
        .record_staged_bound("1.2.3", &staged(directory.path()), "b".repeat(64))
        .unwrap();
    assert!(super::journal_wire::numbered_path(&journal.path, 3, "json").exists());
}

#[test]
fn schema_v1_is_unbound_and_must_be_explicitly_discarded() {
    let directory = tempfile::tempdir().unwrap();
    let journal = UpdateJournal::new(directory.path().join("install-state.json"));
    std::fs::write(
        &journal.path,
        format!(
            r#"{{"schemaVersion":1,"state":"staged","version":"1.2.3","artifactSha256":"{}","stagedPath":"{}"}}"#,
            "a".repeat(64),
            directory.path().join("staged.update").display()
        ),
    )
    .unwrap();
    let record = journal.read().unwrap().unwrap();
    assert!(record.legacy_unbound && record.metadata_sha256.is_none());
    assert_eq!(
        journal.transition(super::super::UpdateInstallState::RestartRequired),
        Err(UpdateJournalError::Corrupt)
    );
    assert!(journal.discard_unbound_legacy().unwrap());
    assert_eq!(journal.read().unwrap(), None);
    journal
        .record_staged("1.2.3", &staged(directory.path()))
        .unwrap();
    assert!(!journal.read().unwrap().unwrap().legacy_unbound);
}

#[test]
fn strict_numbered_names_and_maximum_sequence_fail_closed() {
    let directory = tempfile::tempdir().unwrap();
    let journal = UpdateJournal::new(directory.path().join("install-state.json"));
    for name in [
        "install-state.json.extra.999.json",
        "install-state.json.01.json",
        "install-state.json.1.json.tmp",
    ] {
        std::fs::write(directory.path().join(name), b"ignored").unwrap();
    }
    assert_eq!(journal.next_sequence().unwrap(), 1);
    std::fs::write(
        super::journal_wire::numbered_path(&journal.path, u64::MAX, "tmp"),
        b"partial",
    )
    .unwrap();
    assert_eq!(journal.next_sequence(), Err(UpdateJournalError::Corrupt));
}

#[cfg(unix)]
#[test]
fn journal_symlink_and_fifo_reads_fail_closed_without_blocking() {
    let directory = tempfile::tempdir().unwrap();
    let journal = UpdateJournal::new(directory.path().join("install-state.json"));
    std::os::unix::fs::symlink("missing", &journal.path).unwrap();
    assert!(journal.read().is_err());
    std::fs::remove_file(&journal.path).unwrap();
    assert!(
        std::process::Command::new("mkfifo")
            .arg(&journal.path)
            .status()
            .unwrap()
            .success()
    );
    assert!(journal.read().is_err());
}
