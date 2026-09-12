use std::os::unix::fs::{PermissionsExt as _, symlink};
use std::process::Command;

use super::{open, private_root, uid};
use crate::QualificationReplayLedger;

const JOURNAL: &str = "ledger.sqlite3-journal";

#[test]
fn rejects_journal_symlinks_hardlinks_and_fifos_without_blocking() {
    let symlink_root = private_root();
    let target = symlink_root.path().join("target");
    std::fs::write(&target, []).unwrap();
    symlink(&target, symlink_root.path().join(JOURNAL)).unwrap();
    assert!(QualificationReplayLedger::open_for_test(symlink_root.path(), uid()).is_err());

    let hardlink_root = private_root();
    drop(open(&hardlink_root));
    std::fs::hard_link(
        hardlink_root.path().join(crate::path_guard::DATABASE_NAME),
        hardlink_root.path().join(JOURNAL),
    )
    .unwrap();
    assert!(QualificationReplayLedger::open_for_test(hardlink_root.path(), uid()).is_err());

    let fifo_root = private_root();
    let journal = fifo_root.path().join(JOURNAL);
    assert!(
        Command::new("/usr/bin/mkfifo")
            .arg(&journal)
            .status()
            .unwrap()
            .success()
    );
    assert!(QualificationReplayLedger::open_for_test(fifo_root.path(), uid()).is_err());
}

#[test]
fn retained_journal_witness_rejects_a_replacement() {
    let root = private_root();
    let journal = root.path().join(JOURNAL);
    std::fs::write(&journal, []).unwrap();
    std::fs::set_permissions(&journal, std::fs::Permissions::from_mode(0o600)).unwrap();
    let guarded = crate::path_guard::test_root(root.path(), uid()).unwrap();
    let witness = guarded.open_existing_journal().unwrap();
    std::fs::remove_file(&journal).unwrap();
    std::fs::write(&journal, []).unwrap();
    std::fs::set_permissions(&journal, std::fs::Permissions::from_mode(0o600)).unwrap();
    assert!(guarded.verify_journal_recovered(witness).is_err());
}
