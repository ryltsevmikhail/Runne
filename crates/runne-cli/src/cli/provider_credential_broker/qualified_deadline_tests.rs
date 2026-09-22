use std::io::{Read as _, Write as _};
use std::os::unix::net::UnixStream;
use std::thread;
use std::time::{Duration, Instant};

use super::QualifiedSocketControl;

#[test]
fn blocked_socket_read_is_limited_to_the_remaining_budget() {
    let (_peer, stream) = UnixStream::pair().unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(1)))
        .unwrap();
    let mut control =
        QualifiedSocketControl::with_budget(stream, Duration::from_millis(25)).unwrap();
    let started = Instant::now();
    let error = control.read(&mut [0; 1]).unwrap_err();
    assert!(
        started.elapsed() < Duration::from_millis(250),
        "blocked read exceeded the aggregate deadline: {error}"
    );
}

#[test]
fn finishing_exchange_restores_transport_timeouts() {
    let (_peer, stream) = UnixStream::pair().unwrap();
    let read_timeout = Duration::from_millis(321);
    let write_timeout = Duration::from_millis(654);
    stream.set_read_timeout(Some(read_timeout)).unwrap();
    stream.set_write_timeout(Some(write_timeout)).unwrap();
    let stream = QualifiedSocketControl::new(stream)
        .unwrap()
        .finish()
        .unwrap();
    // SO_RCVTIMEO/SO_SNDTIMEO round to the kernel scheduler tick (up to 4 ms
    // at HZ=250), so the restored values are compared with tick-level
    // tolerance instead of exact equality.
    let restored_read = stream.read_timeout().unwrap().unwrap();
    let restored_write = stream.write_timeout().unwrap().unwrap();
    for (restored, expected) in [
        (restored_read, read_timeout),
        (restored_write, write_timeout),
    ] {
        let drift = restored.abs_diff(expected);
        assert!(
            drift <= Duration::from_millis(8),
            "restored {restored:?} drifted too far from {expected:?}"
        );
    }
}

#[test]
fn expired_exchange_cannot_finish_after_the_last_read() {
    let (mut peer, stream) = UnixStream::pair().unwrap();
    peer.write_all(&[1]).unwrap();
    let mut control =
        QualifiedSocketControl::with_budget(stream, Duration::from_millis(15)).unwrap();
    control.read_exact(&mut [0; 1]).unwrap();
    thread::sleep(Duration::from_millis(25));
    assert!(control.finish().is_err());
}

#[test]
fn blocked_socket_write_is_limited_to_the_remaining_budget() {
    let (_peer, mut stream) = UnixStream::pair().unwrap();
    stream.set_nonblocking(true).unwrap();
    let block = [0_u8; 8_192];
    loop {
        match stream.write(&block) {
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => break,
            Err(error) => panic!("failed to fill socket buffer: {error}"),
        }
    }
    stream.set_nonblocking(false).unwrap();
    stream
        .set_write_timeout(Some(Duration::from_secs(1)))
        .unwrap();
    let mut control =
        QualifiedSocketControl::with_budget(stream, Duration::from_millis(25)).unwrap();
    let started = Instant::now();
    let error = control.write(&[1]).unwrap_err();
    assert!(
        started.elapsed() < Duration::from_millis(250),
        "blocked write exceeded the aggregate deadline: {error}"
    );
}

#[test]
fn trickled_reads_do_not_reset_the_aggregate_budget() {
    let (mut peer, stream) = UnixStream::pair().unwrap();
    let sender = thread::spawn(move || {
        for _ in 0..4 {
            thread::sleep(Duration::from_millis(15));
            if peer.write_all(&[1]).is_err() {
                break;
            }
        }
    });
    let mut control =
        QualifiedSocketControl::with_budget(stream, Duration::from_millis(35)).unwrap();
    let started = Instant::now();
    let error = control.read_exact(&mut [0; 4]).unwrap_err();
    assert!(
        started.elapsed() < Duration::from_millis(250),
        "trickle reset the aggregate deadline: {error}"
    );
    sender.join().unwrap();
}
