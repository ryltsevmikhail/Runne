//! Channel primitive controls only, not evidence of an owner crash history.
use super::*;
use std::net::Shutdown;

#[test]
fn delivered_result_is_received_and_empty_closed_channel_is_not_a_result() {
    let deadline = Deadline::new_supervisor();
    let (mut writer, mut reader) = UnixStream::pair().unwrap();
    send(&mut writer, b"saved-receipt", deadline).unwrap();
    writer.shutdown(Shutdown::Write).unwrap();
    assert_eq!(receive(&mut reader, deadline).unwrap(), b"saved-receipt");
    let (writer, mut reader) = UnixStream::pair().unwrap();
    drop(writer);
    assert_eq!(receive(&mut reader, deadline).unwrap_err().kind(), io::ErrorKind::UnexpectedEof);
}

#[test]
fn zero_response_requires_open_peer_first_then_actual_eof_without_bytes() {
    let deadline = Deadline::new_supervisor();
    let (writer, mut reader) = UnixStream::pair().unwrap();
    no_result_yet(&mut reader, deadline).unwrap();
    drop(writer);
    require_eof_without_bytes(&mut reader, deadline).unwrap();
    assert_eq!(no_result_yet(&mut reader, deadline).unwrap_err().kind(), io::ErrorKind::InvalidData);
}

#[test]
fn any_partial_or_complete_response_byte_refuses_zero_response_qualification() {
    let deadline = Deadline::new_supervisor();
    for raw in [b"x".as_slice(), &[0], &[0, 0, 0], &[0, 0, 0, 1, b'x']] {
        let (mut writer, mut reader) = UnixStream::pair().unwrap();
        writer.write_all(raw).unwrap();
        writer.shutdown(Shutdown::Write).unwrap();
        assert_eq!(require_eof_without_bytes(&mut reader, deadline).unwrap_err().kind(),
            io::ErrorKind::InvalidData);
        let (mut writer, mut reader) = UnixStream::pair().unwrap();
        writer.write_all(raw).unwrap();
        assert_eq!(no_result_yet(&mut reader, deadline).unwrap_err().kind(),
            io::ErrorKind::InvalidData);
    }
}

#[test]
fn request_frames_refuse_partial_extra_zero_and_over_cap_wire_data() {
    let deadline = Deadline::new_supervisor();
    for (raw, expected) in [
        (vec![0], io::ErrorKind::UnexpectedEof),
        (vec![0, 0, 0, 2, b'x'], io::ErrorKind::UnexpectedEof),
        (vec![0, 0, 0, 0], io::ErrorKind::InvalidData),
        (vec![0, 0, 64, 1], io::ErrorKind::InvalidData),
        (vec![0, 0, 0, 1, b'x', b'y'], io::ErrorKind::InvalidData),
    ] {
        let (mut writer, mut reader) = UnixStream::pair().unwrap();
        writer.write_all(&raw).unwrap();
        writer.shutdown(Shutdown::Write).unwrap();
        assert_eq!(receive(&mut reader, deadline).unwrap_err().kind(), expected);
    }
    let (mut writer, mut reader) = UnixStream::pair().unwrap();
    assert_eq!(send(&mut writer, b"", deadline).unwrap_err().kind(), io::ErrorKind::InvalidData);
    assert_eq!(send(&mut writer, &vec![0; 16_385], deadline).unwrap_err().kind(),
        io::ErrorKind::InvalidData);
    no_result_yet(&mut reader, deadline).unwrap();
}

#[test]
fn expired_shared_deadline_refuses_even_ready_io() {
    let expired = Deadline(0);
    let (mut writer, mut reader) = UnixStream::pair().unwrap();
    assert_eq!(send(&mut writer, b"x", expired).unwrap_err().kind(), io::ErrorKind::TimedOut);
    writer.write_all(&[0, 0, 0, 1, b'x']).unwrap();
    writer.shutdown(Shutdown::Write).unwrap();
    assert_eq!(receive(&mut reader, expired).unwrap_err().kind(), io::ErrorKind::TimedOut);
    assert_eq!(no_result_yet(&mut reader, expired).unwrap_err().kind(), io::ErrorKind::TimedOut);
    assert_eq!(require_eof_without_bytes(&mut reader, expired).unwrap_err().kind(),
        io::ErrorKind::TimedOut);
}

// Shorten the existing budget; never construct a new full role budget.
fn short_deadline() -> Deadline {
    let original = Deadline::new_supervisor();
    Deadline::inherited(original.0.checked_sub(7_800_000_000).unwrap())
}

#[test]
fn silent_open_peer_and_missing_frame_shutdown_expire_without_success() {
    let (writer, mut reader) = UnixStream::pair().unwrap();
    assert_eq!(receive(&mut reader, short_deadline()).unwrap_err().kind(),
        io::ErrorKind::TimedOut);
    drop(writer);
    let (writer, mut reader) = UnixStream::pair().unwrap();
    assert_eq!(require_eof_without_bytes(&mut reader, short_deadline()).unwrap_err().kind(),
        io::ErrorKind::TimedOut);
    drop(writer);
    let (mut writer, mut reader) = UnixStream::pair().unwrap();
    writer.write_all(&[0, 0, 0, 1, b'x']).unwrap();
    assert_eq!(receive(&mut reader, short_deadline()).unwrap_err().kind(),
        io::ErrorKind::TimedOut);
    drop(writer);
}

#[test]
fn complete_second_frame_is_not_accepted_as_single_result() {
    let (mut writer, mut reader) = UnixStream::pair().unwrap();
    writer.write_all(&[0, 0, 0, 1, b'x', 0, 0, 0, 1, b'y']).unwrap();
    writer.shutdown(Shutdown::Write).unwrap();
    assert_eq!(receive(&mut reader, Deadline::new_supervisor()).unwrap_err().kind(),
        io::ErrorKind::InvalidData);
}

#[test]
fn exact_payload_cap_roundtrips_with_concurrent_progress() {
    let deadline = Deadline::new_supervisor();
    let (mut writer, mut reader) = UnixStream::pair().unwrap();
    let body = vec![0x5a; 16_384];
    // Both sides use the same deadline; receiving makes progress while sending.
    // Guest watchdog is the independent fatal bound, not a successful join claim.
    std::thread::scope(|scope| {
        let receiver = scope.spawn(|| receive(&mut reader, deadline));
        let sent = send(&mut writer, &body, deadline);
        let closed = writer.shutdown(Shutdown::Write);
        let received = receiver.join().expect("receiver thread panic");
        sent.unwrap();
        closed.unwrap();
        assert_eq!(received.unwrap(), body);
    });
}

#[test]
fn backpressure_preserves_deadline_and_does_not_report_delivery() {
    let (mut writer, _reader) = UnixStream::pair().unwrap();
    writer.set_nonblocking(true).unwrap();
    let deadline = short_deadline();
    let mut saturated = false;
    // Finite setup, no receiver and no unbounded socket fill.
    for _ in 0..256 {
        deadline.check();
        match writer.write(&[0x5a; 1024]) {
            Ok(0) => panic!("zero socket write"),
            Ok(_) => {},
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                saturated = true;
                break;
            },
            Err(error) => panic!("socket fill: {error}"),
        }
    }
    assert!(saturated, "bounded setup did not establish backpressure");
    assert!(deadline.try_remaining().is_ok(), "setup consumed usable budget");
    let mut blocked = 0;
    let result = send_observed(&mut writer, b"result", deadline, || {
        // Scheduling exhaustion refuses this control, never a vacuous PASS.
        assert!(deadline.try_remaining().is_ok(), "no usable budget at WouldBlock");
        blocked += 1;
    });
    assert!(blocked > 0, "send itself never observed live-budget backpressure");
    assert_eq!(result.unwrap_err().kind(), io::ErrorKind::TimedOut);
}
