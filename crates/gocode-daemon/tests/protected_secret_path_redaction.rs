#[path = "support/secret_scan.rs"]
mod secret_scan;

use secret_scan::{RepresentationClass, SecretRepresentation, SecretScanner};

fn scanner(class: RepresentationClass, pattern: &[u8]) -> SecretScanner {
    SecretScanner::new(vec![SecretRepresentation {
        class,
        bytes: pattern.to_vec(),
    }])
    .unwrap_or_else(|_| panic!("valid scanner"))
}

fn panic_text(action: impl FnOnce() + std::panic::UnwindSafe) -> String {
    let payload = std::panic::catch_unwind(action).expect_err("assertion must fail");
    payload
        .downcast_ref::<String>()
        .cloned()
        .or_else(|| payload.downcast_ref::<&str>().map(ToString::to_string))
        .expect("string panic")
}

fn assert_contains_match_metadata(message: &str, sink: &str, class: RepresentationClass) {
    assert!(message.contains(sink));
    assert!(message.contains("pattern_id=0"));
    assert!(message.contains(&format!("representation_class={class}")));
}

#[test]
fn benign_unicode_path_remains_visible_when_file_content_matches() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let path = directory.path().join("benign-visible-file.txt");
    let protected_content = b"protected-file-content";
    std::fs::write(&path, protected_content).expect("fixture file");

    let message = panic_text(|| {
        secret_scan::assert_file_absent(
            &scanner(RepresentationClass::Raw, protected_content),
            "benign file sink",
            &path,
        );
    });

    assert_contains_match_metadata(&message, "benign file sink", RepresentationClass::Raw);
    assert!(message.contains(path.to_str().expect("Unicode fixture path")));
    assert!(!message.contains("<protected-path>"));
    assert!(!message.contains(std::str::from_utf8(protected_content).expect("UTF-8 fixture")));
}

#[test]
fn protected_unicode_filename_redacts_base64_and_hex_cases() {
    let cases = [
        (
            RepresentationClass::Base64,
            "cHJvdGVjdGVkLWJhc2U2NC1maWxlbmFtZQ==",
            "base64 file sink",
        ),
        (
            RepresentationClass::LowerHex,
            "70726f7465637465642d6865782d66696c656e616d65",
            "hex file sink",
        ),
    ];

    for (class, protected_representation, sink) in cases {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory
            .path()
            .join(format!("prefix-{protected_representation}.txt"));
        std::fs::write(&path, protected_representation).expect("fixture file");

        let message = panic_text(|| {
            secret_scan::assert_file_absent(
                &scanner(class, protected_representation.as_bytes()),
                sink,
                &path,
            );
        });

        assert_contains_match_metadata(&message, sink, class);
        assert!(message.contains("<protected-path>"));
        assert!(!message.contains(path.to_str().expect("Unicode fixture path")));
        assert!(!message.contains(protected_representation));
    }
}

#[test]
fn nonexistent_protected_unicode_filename_redacts_open_failure() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let protected_representation = "cHJvdGVjdGVkLW1pc3NpbmctZmlsZW5hbWU=";
    let path = directory
        .path()
        .join(format!("missing-{protected_representation}.txt"));

    let message = panic_text(|| {
        secret_scan::assert_file_absent(
            &scanner(
                RepresentationClass::Base64,
                protected_representation.as_bytes(),
            ),
            "missing file sink",
            &path,
        );
    });

    assert!(message.contains("missing file sink"));
    assert!(message.contains("<protected-path>"));
    assert!(message.contains("NotFound"));
    assert!(!message.contains(path.to_str().expect("Unicode fixture path")));
    assert!(!message.contains(protected_representation));
    assert!(!message.contains("No such file"));
}

#[cfg(unix)]
#[test]
fn non_unicode_path_redacts_raw_os_bytes() {
    use std::os::unix::ffi::OsStringExt;

    let directory = tempfile::tempdir().expect("temporary directory");
    let raw_name = b"nonunicode-\xff-file";
    let path = directory
        .path()
        .join(std::ffi::OsString::from_vec(raw_name.to_vec()));
    let protected_content = b"protected-nonunicode-content";
    std::fs::write(&path, protected_content).expect("fixture file");

    let message = panic_text(|| {
        secret_scan::assert_file_absent(
            &scanner(RepresentationClass::Raw, protected_content),
            "nonunicode file sink",
            &path,
        );
    });

    assert_contains_match_metadata(&message, "nonunicode file sink", RepresentationClass::Raw);
    assert!(message.contains("<unavailable-path>"));
    assert!(!message.contains("nonunicode-"));
    assert!(!message.contains(String::from_utf8_lossy(raw_name).as_ref()));
    assert!(!message.contains('\u{fffd}'));
    assert!(!message.contains(std::str::from_utf8(protected_content).expect("UTF-8 fixture")));
}
