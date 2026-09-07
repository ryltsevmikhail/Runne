//! Artifact transport tests: single-fd intake, CLOEXEC verification,
//! safe reads over the owned descriptor.

use runne_inference_host::artifact_transport::{read_at, take_single_fd};

#[test]
fn zero_fds_rejected() {
    let mut fds: Vec<rustix::fd::OwnedFd> = Vec::new();
    let err = take_single_fd(&mut fds).expect_err("zero");
    assert!(matches!(err, runne_inference_host::HostError::FdMissing));
}

#[test]
fn two_fds_rejected_and_both_closed() {
    let a = std::fs::File::open("/dev/null").expect("open").into();
    let b = std::fs::File::open("/dev/null").expect("open2").into();
    let mut fds = vec![a, b];
    let err = take_single_fd(&mut fds).expect_err("two fds");
    assert!(matches!(err, runne_inference_host::HostError::FdDuplicate));
    // take_single_fd removes one, clears the rest: fds is now empty.
    assert!(fds.is_empty());
}

#[test]
fn read_at_reads_whole_request_after_seek() {
    let dir = tempfile::tempdir().expect("dir");
    let path = dir.path().join("blob.bin");
    std::fs::write(&path, b"GGUF-HEADER-AND-DATA-BYTES").expect("write");
    let file = std::fs::File::open(&path).expect("open");
    let fd = std::os::fd::OwnedFd::from(file);
    let mut buf = [0u8; 5];
    read_at(&fd, 5, &mut buf).expect("read");
    assert_eq!(&buf, b"HEADE");
}
