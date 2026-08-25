#![cfg(windows)]

use std::path::Path;

use runne_windows_native_handle::{DirectoryHandle, NativeDirectoryEntryKind};

#[test]
fn enumerates_and_reads_handle_relative_entries() {
    let directory = tempfile::tempdir().expect("temporary directory");
    std::fs::create_dir(directory.path().join("src")).expect("source directory");
    std::fs::write(directory.path().join("README.md"), "hello\n").expect("text file");
    let root = DirectoryHandle::open(directory.path()).expect("root handle");

    let entries = root.list_entries(8).expect("root entries");
    assert_eq!(entries.len(), 2);
    assert!(entries.iter().any(|entry| {
        entry.name() == Path::new("README.md").as_os_str()
            && entry.kind() == NativeDirectoryEntryKind::File
            && entry.size_bytes() == 6
    }));
    assert!(entries.iter().any(|entry| {
        entry.name() == Path::new("src").as_os_str()
            && entry.kind() == NativeDirectoryEntryKind::Directory
    }));
    assert_eq!(
        root.read_relative_file(Path::new("README.md"), 64)
            .expect("read file"),
        b"hello\n"
    );
}

#[test]
fn rejects_traversal_and_bounded_reads() {
    let directory = tempfile::tempdir().expect("temporary directory");
    std::fs::write(directory.path().join("large"), "123456").expect("large file");
    let root = DirectoryHandle::open(directory.path()).expect("root handle");

    assert!(root.read_relative_file(Path::new("../large"), 64).is_err());
    assert!(root.read_relative_file(Path::new("large"), 3).is_err());
}
