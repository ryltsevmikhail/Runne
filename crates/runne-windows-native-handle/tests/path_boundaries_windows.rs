#![cfg(windows)]

//! Windows regressions for the remaining native path boundaries behind the
//! T1 admission: trailing dots/spaces, alternate data streams, device/UNC
//! anchors, reparse-point (junction/symlink) escape, and traversal shapes.
//!
//! Every probe runs through the same production primitives the broker uses
//! (`DirectoryHandle::open`, `read_relative_file`, `list_entries`) on
//! disposable fixtures with synthetic content. The facts pinned here were
//! observed on the qualification platform (NTFS, per-directory
//! case-insensitive, 8dot3 generation disabled on C:).

use std::fs;
use std::path::Path;

use runne_windows_native_handle::{DirectoryHandle, NativeDirectoryEntryKind, NativeHandleError};

const DENIED_ID_RSA: &[u8] = b"runne-synthetic-denied id_rsa v1\n";
const PLAIN_CONTENT: &[u8] = b"runne-synthetic-plain content v1\n";
const OUTSIDE_CONTENT: &[u8] = b"runne-synthetic-outside workspace content v1\n";

fn open_root(path: &Path) -> DirectoryHandle {
    DirectoryHandle::open(path).expect("root directory handle")
}

fn read_via_native(root: &Path, name: &str) -> Result<Vec<u8>, NativeHandleError> {
    open_root(root).read_relative_file(Path::new(name), 4096)
}

fn write_plain(root: &Path, name: &str, content: &[u8]) {
    fs::write(root.join(name), content).unwrap_or_else(|error| panic!("create {name}: {error}"));
}

#[test]
fn trailing_dots_and_spaces_never_resolve_to_the_denied_file() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let root = directory.path();
    write_plain(root, "id_rsa", DENIED_ID_RSA);

    // Win32 layers strip trailing dots/spaces; the NT object space must not.
    // A read through the native layer for such a component either names a
    // distinct missing object (miss) or is rejected — it must never deliver
    // the denied file's bytes.
    for name in ["id_rsa.", "id_rsa ", "id_rsa. .", "id_rsa..."] {
        match read_via_native(root, name) {
            Ok(bytes) => panic!(
                "{name:?} must not resolve to denied content; got {} bytes",
                bytes.len()
            ),
            Err(NativeHandleError::Rejected) => {}
            Err(error) => panic!("unexpected native error for {name:?}: {error:?}"),
        }
    }
    assert_eq!(
        read_via_native(root, "id_rsa").expect("canonical denied file must stay openable"),
        DENIED_ID_RSA
    );
}

#[test]
fn alternate_data_stream_components_are_rejected() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let root = directory.path();
    write_plain(root, "notes.txt", PLAIN_CONTENT);

    // The stream exists on the volume; the ':' component grammar must keep
    // every stream spelling out of the handle-relative reader.
    let cmd = std::process::Command::new("cmd")
        .args(["/C", "echo runne-synthetic-stream>notes.txt:s1"])
        .current_dir(root)
        .output()
        .expect("spawn cmd for stream fixture");
    assert!(cmd.status.success(), "stream fixture setup failed");

    for name in ["notes.txt:s1", "notes.txt:$DATA", "notes.txt::s1"] {
        assert!(
            read_via_native(root, name).is_err(),
            "{name} must be rejected by the component grammar"
        );
    }
    assert_eq!(
        read_via_native(root, "notes.txt").expect("base file must stay openable"),
        PLAIN_CONTENT
    );
}

#[test]
fn unc_device_and_non_drive_anchors_are_rejected() {
    for anchor in [
        "\\\\?\\C:\\Windows",
        "\\\\.\\C:\\",
        "\\\\localhost\\c$\\Windows",
        "\\\\.\\pipe\\runne-probe",
        "relative\\anchor",
        "C:relative",
    ] {
        assert!(
            DirectoryHandle::open(Path::new(anchor)).is_err(),
            "anchor {anchor:?} must be rejected"
        );
    }
}

#[test]
fn junction_component_escape_is_fail_closed() {
    let outside = tempfile::tempdir().expect("outside temporary directory");
    write_plain(outside.path(), "secret.txt", OUTSIDE_CONTENT);

    let directory = tempfile::tempdir().expect("workspace temporary directory");
    let root = directory.path();
    write_plain(root, "inside.txt", PLAIN_CONTENT);
    let link = root.join("escape");
    let output = std::process::Command::new("cmd")
        .args([
            "/C",
            "mklink",
            "/J",
            &link.to_string_lossy(),
            &outside.path().to_string_lossy(),
        ])
        .output()
        .expect("spawn cmd for junction fixture");
    assert!(output.status.success(), "junction fixture setup failed");

    // Traversal through the junction must fail closed at every surface.
    assert!(
        read_via_native(root, "escape\\secret.txt").is_err(),
        "reading through a junction must be rejected"
    );
    assert!(
        open_root(root)
            .open_relative_directory(Path::new("escape"))
            .is_err(),
        "opening the junction as a directory must be rejected"
    );
    assert!(
        open_root(root).list_entries(16).is_err(),
        "listing a directory containing a reparse point must fail closed"
    );
    assert_eq!(
        read_via_native(root, "inside.txt").expect("regular files must stay readable"),
        PLAIN_CONTENT
    );
}

#[test]
fn symlink_leaf_escape_is_fail_closed() {
    let outside = tempfile::tempdir().expect("outside temporary directory");
    let outside_file = outside.path().join("secret.txt");
    fs::write(&outside_file, OUTSIDE_CONTENT).expect("outside fixture");

    let directory = tempfile::tempdir().expect("workspace temporary directory");
    let root = directory.path();
    write_plain(root, "inside.txt", PLAIN_CONTENT);
    // A directory symlink is a reparse point the same way a junction is; a
    // file symlink exercises the leaf (`open_relative_file`) path.
    let output = std::process::Command::new("cmd")
        .args([
            "/C",
            "mklink",
            &root.join("linked.txt").to_string_lossy(),
            &outside_file.to_string_lossy(),
        ])
        .output()
        .expect("spawn cmd for symlink fixture");
    assert!(output.status.success(), "symlink fixture setup failed");

    assert!(
        read_via_native(root, "linked.txt").is_err(),
        "reading a symlink leaf must be rejected"
    );
    assert!(
        open_root(root).list_entries(16).is_err(),
        "listing a directory containing a symlink must fail closed"
    );
}

#[test]
fn traversal_and_relative_escape_shapes_are_rejected() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let root = directory.path();
    fs::create_dir(root.join("sub")).expect("subdirectory");
    write_plain(root, "id_rsa", DENIED_ID_RSA);
    write_plain(&root.join("sub"), "note.txt", PLAIN_CONTENT);

    for name in [
        "sub\\..\\id_rsa",
        "sub\\..",
        "..\\id_rsa",
        "sub\\.\\note.txt",
    ] {
        assert!(
            read_via_native(root, name).is_err(),
            "traversal shape {name:?} must be rejected"
        );
    }
    assert_eq!(
        read_via_native(root, "sub\\note.txt").expect("nested regular read must work"),
        PLAIN_CONTENT
    );
}

#[test]
fn listing_reports_real_names_and_rejects_reparse_entries() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let root = directory.path();
    write_plain(root, "regular.txt", PLAIN_CONTENT);

    let entries = open_root(root).list_entries(16).expect("entries");
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].name(), Path::new("regular.txt").as_os_str());
    assert_eq!(entries[0].kind(), NativeDirectoryEntryKind::File);
    assert_eq!(entries[0].size_bytes(), PLAIN_CONTENT.len() as u64);
}
