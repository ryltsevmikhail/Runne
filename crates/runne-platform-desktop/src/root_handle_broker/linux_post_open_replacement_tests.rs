use std::fs;
use std::io::Read;

use super::{RootHandleBrokerError, VerifiedRootHandle, platform::open_file_below};

#[test]
fn opened_file_descriptor_survives_file_and_parent_replacement() {
    let directory = tempfile::tempdir().unwrap();
    let root_path = directory.path().join("root");
    let outside = directory.path().join("outside");
    fs::create_dir(&root_path).unwrap();
    fs::create_dir(&outside).unwrap();
    let root = VerifiedRootHandle::open(&root_path).unwrap();

    let selected = root_path.join("selected.txt");
    let hostile = outside.join("hostile.txt");
    fs::write(&selected, b"admitted file bytes").unwrap();
    fs::write(&hostile, b"outside replacement bytes").unwrap();
    let mut opened = open_file_below(&root.handle, std::path::Path::new("selected.txt")).unwrap();
    fs::remove_file(&selected).unwrap();
    std::os::unix::fs::symlink(&hostile, &selected).unwrap();
    let mut bytes = String::new();
    opened.read_to_string(&mut bytes).unwrap();
    assert_eq!(bytes, "admitted file bytes");
    assert!(matches!(
        open_file_below(&root.handle, std::path::Path::new("selected.txt")),
        Err(RootHandleBrokerError::Rejected)
    ));

    let selected_directory = root_path.join("nested");
    let moved_directory = root_path.join("nested-moved");
    let outside_directory = outside.join("nested");
    fs::create_dir(&selected_directory).unwrap();
    fs::create_dir(&outside_directory).unwrap();
    fs::write(
        selected_directory.join("document.txt"),
        b"admitted nested bytes",
    )
    .unwrap();
    fs::write(
        outside_directory.join("document.txt"),
        b"hostile nested bytes",
    )
    .unwrap();
    let mut opened =
        open_file_below(&root.handle, std::path::Path::new("nested/document.txt")).unwrap();
    fs::rename(&selected_directory, &moved_directory).unwrap();
    std::os::unix::fs::symlink(&outside_directory, &selected_directory).unwrap();
    let mut bytes = String::new();
    opened.read_to_string(&mut bytes).unwrap();
    assert_eq!(bytes, "admitted nested bytes");
    assert!(matches!(
        open_file_below(&root.handle, std::path::Path::new("nested/document.txt")),
        Err(RootHandleBrokerError::Rejected)
    ));
}
