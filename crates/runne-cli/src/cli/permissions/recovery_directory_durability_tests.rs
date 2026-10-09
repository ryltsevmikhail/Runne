use super::*;

#[test]
fn existing_directory_sync_failure_is_not_accepted() {
    let base = std::env::temp_dir().join(format!(
        "runne-cli-sync-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir(&base).unwrap();
    let parent = openat(
        rustix::fs::CWD,
        &base,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
    )
    .unwrap();
    let mut syncs = 0;
    assert!(
        open_directory_with_sync(&parent, "scope", true, true, |_| {
            syncs += 1;
            Ok(())
        })
        .unwrap()
        .is_some()
    );
    assert!(matches!(
        open_directory_with_sync(&parent, "scope", true, true, |_| {
            syncs += 1;
            Err(RecoveryError::Io)
        }),
        Err(RecoveryError::Io)
    ));
    assert_eq!(syncs, 2);
    drop(parent);
    std::fs::remove_dir_all(base).unwrap();
}
