use std::path::Path;
use std::process::Command;

use super::{binding, fixture, open, private_root, uid};
use crate::QualificationReplayLedger;

fn chmod_acl(arguments: &[&str], path: &Path) {
    assert!(
        Command::new("/bin/chmod")
            .args(arguments)
            .arg(path)
            .status()
            .unwrap()
            .success()
    );
}

#[test]
fn rejects_existing_ledger_file_and_root_directory_acls() {
    let root = private_root();
    chmod_acl(&["-N"], root.path());
    chmod_acl(&["+a", "everyone deny delete"], root.path());
    assert!(QualificationReplayLedger::open_for_test(root.path(), uid()).is_err());
    chmod_acl(&["-N"], root.path());

    drop(open(&root));
    let database = root.path().join(crate::path_guard::DATABASE_NAME);
    chmod_acl(&["-N"], &database);
    chmod_acl(&["+a", "everyone deny write"], &database);
    assert!(QualificationReplayLedger::open_for_test(root.path(), uid()).is_err());
    chmod_acl(&["-N"], &database);
}

#[test]
fn rechecks_root_and_database_acls_after_opening() {
    let root = private_root();
    let mut ledger = open(&root);
    chmod_acl(&["-N"], root.path());
    chmod_acl(&["+a", "everyone deny delete"], root.path());
    assert!(
        ledger
            .consume_fault(fixture::facts([1, 2, 3, 4]), binding(5, 6))
            .is_err()
    );
    chmod_acl(&["-N"], root.path());

    let mut ledger = open(&root);
    let database = root.path().join(crate::path_guard::DATABASE_NAME);
    chmod_acl(&["-N"], &database);
    chmod_acl(&["+a", "everyone deny write"], &database);
    assert!(
        ledger
            .consume_fault(fixture::facts([5, 6, 7, 8]), binding(5, 6))
            .is_err()
    );
    chmod_acl(&["-N"], &database);
}
