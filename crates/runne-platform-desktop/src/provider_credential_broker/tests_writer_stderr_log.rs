//! Safe unit coverage for the fixture-owned writer stderr log: every check
//! runs inside a private `tempfile` namespace; no launchd, no shared `/tmp`,
//! no spawned writers.

use std::io::Write as _;
use std::os::fd::OwnedFd;
use std::os::unix::fs::PermissionsExt as _;

use super::writer_stderr_log::open_fixture_writer_stderr_log;

fn private_root() -> tempfile::TempDir {
    let directory = tempfile::tempdir().expect("private fixture root");
    std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))
        .expect("fixture root mode");
    directory
}

fn write_all(descriptor: &OwnedFd, bytes: &[u8]) {
    let mut copy = std::fs::File::from(descriptor.try_clone().expect("clone log fd"));
    copy.write_all(bytes).expect("append write");
}

#[test]
fn log_is_created_private_append_only_and_verified() {
    let root = private_root();
    let log_path = root.path().join("writer-stderr.log");

    let first = open_fixture_writer_stderr_log(root.path()).expect("first open");
    write_all(&first, b"a");
    drop(first);
    let second = open_fixture_writer_stderr_log(root.path()).expect("reopen appends");
    write_all(&second, b"b");
    drop(second);

    let contents = std::fs::read(&log_path).expect("log contents");
    assert_eq!(contents, b"ab", "log must be append-only across opens");
    let mode = std::fs::metadata(&log_path)
        .expect("log metadata")
        .permissions()
        .mode();
    assert_eq!(mode & 0o777, 0o600, "log must stay exactly 0600");
}

#[test]
fn symlinked_log_file_is_rejected() {
    let root = private_root();
    let target = root.path().join("target.log");
    std::fs::write(&target, b"attacker").expect("target");
    std::os::unix::fs::symlink(&target, root.path().join("writer-stderr.log"))
        .expect("symlinked log");

    assert!(open_fixture_writer_stderr_log(root.path()).is_err());
}

#[test]
fn symlinked_fixture_root_is_rejected() {
    let real = private_root();
    let link_parent = tempfile::tempdir().expect("link parent");
    let root = link_parent.path().join("fixture-root-link");
    std::os::unix::fs::symlink(real.path(), &root).expect("symlinked root");

    assert!(open_fixture_writer_stderr_log(&root).is_err());
}

#[test]
fn returned_descriptor_is_raised_above_the_reserved_range() {
    let root = private_root();
    let log = open_fixture_writer_stderr_log(root.path()).expect("raised log fd");
    let raw = std::os::fd::AsRawFd::as_raw_fd(&log);
    assert!(
        raw >= 4,
        "log fd {raw} may collide with stdin/stdout/stderr or the fd 3 secret slot"
    );
}

/// Source guard: the raise must stay in the open path, because a dynamic
/// low-fd collision cannot be forced deterministically inside this process.
#[test]
fn log_descriptor_is_duplicated_above_reserved_range_in_source() {
    let source = include_str!("writer_stderr_log.rs");
    assert!(
        source.contains("fcntl_dupfd_cloexec(&descriptor, 4)"),
        "the log fd raise above the reserved 0..=3 range was removed"
    );
}

#[test]
fn symlinked_parent_of_fixture_root_is_rejected() {
    let holder = tempfile::tempdir().expect("holder");
    let real_parent = holder.path().join("real-parent");
    std::fs::create_dir(&real_parent).expect("real parent");
    std::fs::set_permissions(&real_parent, std::fs::Permissions::from_mode(0o700))
        .expect("parent mode");
    let root = real_parent.join("fixture-root");
    std::fs::create_dir(&root).expect("fixture root exists through the real parent");
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).expect("root mode");
    // Control: the identical namespace passes when reached without a symlink.
    assert!(open_fixture_writer_stderr_log(&root).is_ok());

    let parent_alias = holder.path().join("parent-link");
    std::os::unix::fs::symlink(&real_parent, &parent_alias).expect("symlinked parent");
    let aliased_root = parent_alias.join("fixture-root");

    assert!(open_fixture_writer_stderr_log(&aliased_root).is_err());
}

#[test]
fn group_accessible_parent_of_fixture_root_is_rejected() {
    let holder = tempfile::tempdir().expect("holder");
    let parent = holder.path().join("shared-parent");
    std::fs::create_dir(&parent).expect("parent");
    std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o750))
        .expect("widened parent mode");
    let root = parent.join("fixture-root");
    std::fs::create_dir(&root).expect("root");
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).expect("root mode");

    assert!(open_fixture_writer_stderr_log(&root).is_err());
}

#[test]
fn widened_log_mode_is_rejected() {
    let root = private_root();
    let log_path = root.path().join("writer-stderr.log");
    std::fs::write(&log_path, b"").expect("pre-existing log");
    std::fs::set_permissions(&log_path, std::fs::Permissions::from_mode(0o644))
        .expect("widened mode");

    assert!(open_fixture_writer_stderr_log(root.path()).is_err());
}

#[test]
fn missing_or_non_directory_fixture_root_is_rejected() {
    let holder = tempfile::tempdir().expect("holder");
    let file_root = holder.path().join("file-root");
    std::fs::write(&file_root, b"not a directory").expect("file as root");

    assert!(open_fixture_writer_stderr_log(&holder.path().join("absent-root")).is_err());
    assert!(open_fixture_writer_stderr_log(&file_root).is_err());
}

#[test]
fn group_accessible_fixture_root_is_rejected() {
    let root = private_root();
    std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o750))
        .expect("widened root mode");

    assert!(open_fixture_writer_stderr_log(root.path()).is_err());
}
