//! Unit tests for the Seatbelt profile renderer.

use std::fs;
use std::path::Path;

use crate::containment::ContainmentError;

use super::MacOsSeatbeltProfileV1;

#[test]
fn renders_a_workspace_confined_profile() {
    let directory = tempfile::tempdir().expect("temporary workspace");
    let workspace = fs::canonicalize(directory.path()).expect("canonical workspace");
    let profile = MacOsSeatbeltProfileV1::new(&workspace)
        .expect("workspace profile")
        .render();

    assert!(profile.contains("(deny default)"));
    assert!(profile.contains("(deny network*)"));
    assert!(profile.contains("(literal \"/\")"));
    let workspace_rule = format!("(subpath \"{}\")", workspace.display());
    assert_eq!(profile.matches(&workspace_rule).count(), 2);
}

#[test]
fn escapes_quotes_and_backslashes_in_paths() {
    let directory = tempfile::tempdir().expect("temporary workspace");
    let workspace = directory.path().join("quoted\"path\\");
    fs::create_dir(&workspace).expect("create quoted workspace");
    let workspace = fs::canonicalize(&workspace).expect("canonical workspace");
    let profile = MacOsSeatbeltProfileV1::new(&workspace)
        .expect("workspace profile")
        .render();

    assert!(profile.contains("quoted\\\"path\\\\"));
    assert!(!profile.contains("quoted\"path"));
}

#[test]
fn rejects_a_relative_workspace() {
    assert!(matches!(
        MacOsSeatbeltProfileV1::new(Path::new("relative/workspace")),
        Err(ContainmentError::ProfileUnsupported(_))
    ));
}

#[test]
fn rejects_a_regular_file_as_a_workspace() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let file = directory.path().join("file");
    fs::write(&file, b"not a directory").expect("create file");

    assert!(matches!(
        MacOsSeatbeltProfileV1::new(&file),
        Err(ContainmentError::ProfileUnsupported(_))
    ));
}

#[test]
fn rejects_a_control_character_in_a_path() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let workspace = directory.path().join("line\nbreak");
    fs::create_dir(&workspace).expect("create workspace");

    assert!(matches!(
        MacOsSeatbeltProfileV1::new(&workspace),
        Err(ContainmentError::ProfileUnsupported(_))
    ));
}

#[test]
fn admits_additional_read_and_write_roots() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let workspace = directory.path().join("workspace");
    let read_only = directory.path().join("read-only");
    let writable = directory.path().join("writable");
    fs::create_dir(&workspace).expect("create workspace");
    fs::create_dir(&read_only).expect("create read-only root");
    fs::create_dir(&writable).expect("create writable root");

    let mut profile = MacOsSeatbeltProfileV1::new(&workspace).expect("workspace profile");
    profile.allow_read_root(&read_only).expect("read-only root");
    profile.allow_write_root(&writable).expect("writable root");
    let rendered = profile.render();

    assert!(rendered.contains(&format!(
        "(subpath \"{}\")",
        fs::canonicalize(&read_only).expect("canonical read-only").display()
    )));
    assert!(rendered.contains(&format!(
        "(subpath \"{}\")",
        fs::canonicalize(&writable).expect("canonical writable").display()
    )));
}
