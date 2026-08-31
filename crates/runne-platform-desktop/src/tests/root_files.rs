use std::fs;
use std::path::Path;

use crate::VerifiedRootHandle;

fn open_temp_root(path: &Path) -> VerifiedRootHandle {
    let canonical_path = fs::canonicalize(path).unwrap();
    VerifiedRootHandle::open(&canonical_path).unwrap()
}

#[test]
fn verified_root_reads_text_and_lists_only_handle_relative_entries() {
    let directory = tempfile::tempdir().unwrap();
    fs::create_dir(directory.path().join("src")).unwrap();
    fs::write(directory.path().join("src/lib.rs"), "fn main() {}\n").unwrap();
    let root = open_temp_root(directory.path());
    let root_entries = root.list_root(10).unwrap();
    assert_eq!(root_entries[0].relative_path(), "src");
    assert_eq!(root.list_root(10).unwrap(), root_entries);
    let entries = root.list_relative("src", 10).unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].relative_path(), "src/lib.rs");
    assert_eq!(entries[0].size_bytes(), 13);
    assert_eq!(root.read_text_relative("src/lib.rs", 100).unwrap(), "fn main() {}\n");
}

#[test]
fn verified_root_rejects_escape_and_oversized_content() {
    let directory = tempfile::tempdir().unwrap();
    fs::write(directory.path().join("secret"), "secret").unwrap();
    let root = open_temp_root(directory.path());
    assert!(root.list_relative("../", 10).is_err());
    assert!(root.list_root(0).is_err());
    assert!(root.read_text_relative("../secret", 100).is_err());
    fs::write(directory.path().join("large"), "123456").unwrap();
    assert!(root.read_text_relative("large", 5).is_err());
}

#[cfg(unix)]
#[test]
fn verified_root_rejects_symlink_entries_and_reads() {
    use std::os::unix::fs::symlink;
    let directory = tempfile::tempdir().unwrap();
    fs::write(directory.path().join("outside"), "outside").unwrap();
    symlink(directory.path().join("outside"), directory.path().join("link")).unwrap();
    let root = open_temp_root(directory.path());
    assert!(root.list_relative("", 10).is_err());
    assert!(root.list_root(10).is_err());
    assert!(root.read_text_relative("link", 100).is_err());
}
