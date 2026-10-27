use super::*;

#[test]
fn late_stderr_is_drained_to_eof_after_the_collected_failure_boundary() {
    // Guest-only anonymous IPC regression, no actual Child/exit witness.
    let (input, input_peer) = UnixStream::pair().unwrap();
    let (output, output_peer) = UnixStream::pair().unwrap();
    let (mut errors, mut error_peer) = UnixStream::pair().unwrap();
    output.set_nonblocking(true).unwrap();
    errors.set_nonblocking(true).unwrap();
    let mut probe = [0u8; 1];
    assert_eq!(
        errors.read(&mut probe).unwrap_err().kind(),
        ErrorKind::WouldBlock
    );
    error_peer.write_all(b"late close failure").unwrap();
    drop(error_peer);
    drop(output_peer);
    drop(input_peer);
    let mut sockets = Sockets {
        input,
        output,
        errors,
    };
    let (mut out, mut err) = (Vec::new(), Vec::new());
    let (mut out_eof, mut err_eof) = (false, false);
    drain_after_collected_failure(
        &mut sockets,
        &mut out,
        &mut err,
        &mut out_eof,
        &mut err_eof,
        Deadline::new_supervisor(),
    )
    .unwrap();
    assert!(out_eof && err_eof && out.is_empty());
    assert_eq!(err, b"late close failure");
}
