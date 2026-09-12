use std::fs::File;
use std::os::fd::AsFd;
use std::path::Path;
use std::process::Command;

use super::require_no_extended_acl;

fn chmod(arguments: &[&str], path: &Path) {
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
fn rejects_acl_despite_readonly_mode_and_rechecks_the_same_descriptor() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("policy");
    let file = File::create(&path).unwrap();
    chmod(&["-N"], &path);
    chmod(&["0444"], &path);
    require_no_extended_acl(file.as_fd()).unwrap();
    chmod(&["+a", "everyone allow write,append"], &path);
    assert!(require_no_extended_acl(file.as_fd()).is_err());
    chmod(&["-N"], &path);
    require_no_extended_acl(file.as_fd()).unwrap();
}

#[test]
fn rejects_directory_acl_without_resolving_principals_or_allow_rules() {
    let directory = tempfile::tempdir().unwrap();
    let file = File::open(directory.path()).unwrap();
    chmod(&["-N"], directory.path());
    require_no_extended_acl(file.as_fd()).unwrap();
    chmod(&["+a", "everyone deny delete"], directory.path());
    assert!(require_no_extended_acl(file.as_fd()).is_err());
    chmod(&["-N"], directory.path());
}

#[test]
fn native_query_error_is_never_admitted() {
    // SAFETY: the native shim accepts an integer and handles OS errors. No invalid
    // BorrowedFd is constructed, and this call cannot close any descriptor.
    assert_eq!(unsafe { super::runne_macos_fd_has_no_extended_acl(-1) }, 0);
}
