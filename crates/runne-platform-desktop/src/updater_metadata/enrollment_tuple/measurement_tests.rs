use std::fs::OpenOptions;
use std::path::Path;

use super::*;

fn open_regular_file(path: &Path) -> Result<File, NativeEnrollmentTupleError> {
    #[cfg(unix)]
    let file = {
        use std::os::unix::fs::OpenOptionsExt;
        OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(path)
    };
    #[cfg(windows)]
    let file = {
        use std::os::windows::fs::OpenOptionsExt;
        OpenOptions::new()
            .read(true)
            .custom_flags(0x0020_0000)
            .open(path)
    };
    #[cfg(not(any(unix, windows)))]
    let file = OpenOptions::new().read(true).open(path);
    let file = file.map_err(|_| NativeEnrollmentTupleError::Rejected)?;
    OpenedNativeEnrollmentFile::new(file).map(|opened| opened.file)
}

#[test]
fn refuses_oversized_native_role() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("role");
    File::create(&path)
        .unwrap()
        .set_len(MAX_NATIVE_ROLE_BYTES + 1)
        .unwrap();
    assert!(open_regular_file(&path).is_err());
}

#[cfg(unix)]
#[test]
fn identity_mismatch_is_detected() {
    let directory = tempfile::tempdir().unwrap();
    let first = directory.path().join("first");
    let second = directory.path().join("second");
    std::fs::write(&first, b"first").unwrap();
    std::fs::write(&second, b"second").unwrap();
    assert!(!same_identity(
        &std::fs::metadata(first).unwrap(),
        &std::fs::metadata(second).unwrap()
    ));
}

#[cfg(windows)]
#[test]
fn identity_mismatch_is_detected() {
    let directory = tempfile::tempdir().unwrap();
    let first = directory.path().join("first");
    let second = directory.path().join("second");
    std::fs::write(&first, b"first").unwrap();
    std::fs::write(&second, b"second").unwrap();
    let opened = OpenedNativeEnrollmentFile::new(open_regular_file(&first).unwrap()).unwrap();
    let reopened = OpenedNativeEnrollmentFile::new(open_regular_file(&first).unwrap()).unwrap();
    assert!(opened.matches_opened(&reopened).unwrap());
    assert!(
        !opened
            .matches_file(&open_regular_file(&second).unwrap())
            .unwrap()
    );
}

#[cfg(windows)]
#[test]
fn replacement_at_same_path_is_detected() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("role");
    std::fs::write(&path, b"original").unwrap();
    let opened = OpenedNativeEnrollmentFile::new(open_regular_file(&path).unwrap()).unwrap();
    std::fs::remove_file(&path).unwrap();
    std::fs::write(&path, b"replacement").unwrap();
    assert!(
        !opened
            .matches_file(&open_regular_file(&path).unwrap())
            .unwrap()
    );
}

#[cfg(windows)]
#[test]
fn measured_digest_and_read_bytes_follow_the_file_content() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("role");
    std::fs::write(&path, b"measured payload").unwrap();
    let opened = OpenedNativeEnrollmentFile::new(open_regular_file(&path).unwrap()).unwrap();
    let digest = opened.measure().unwrap();
    assert_eq!(digest, hex::encode(Sha256::digest(b"measured payload")));
    assert_eq!(opened.read_bytes(1024).unwrap(), b"measured payload");
}
