#![cfg(test)]

use std::io::Write as _;
use std::os::fd::AsFd as _;
use std::os::unix::net::UnixStream;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use super::support::{SHORT_DEADLINE, send_with_descriptors, valid_frame};

const WATCHDOG: Duration = Duration::from_secs(2);
const MAX_EXPECTED: Duration = Duration::from_secs(1);

#[test]
fn no_data_partial_frame_and_missing_eof_share_a_bounded_receive() {
    for case in 0..3 {
        let (mut sender, receiver) = UnixStream::pair().expect("transport pair");
        let mut offered = None;
        match case {
            0 => {}
            1 => sender
                .write_all(&valid_frame()[..7])
                .expect("partial frame"),
            2 => {
                let (endpoint, _) = UnixStream::pair().expect("offered endpoint");
                send_with_descriptors(&sender, &valid_frame(), &[endpoint.as_fd()]);
                offered = Some(endpoint);
            }
            _ => unreachable!(),
        }
        let (release, wait) = mpsc::channel();
        let watchdog = thread::spawn(move || {
            let _ = wait.recv_timeout(WATCHDOG);
            drop((sender, offered));
        });

        let started = Instant::now();
        assert!(
            crate::writer_endpoint_handoff::receive_for_test(&receiver, SHORT_DEADLINE).is_err()
        );
        let elapsed = started.elapsed();
        let _ = release.send(());
        watchdog.join().expect("watchdog");
        assert!(
            elapsed < MAX_EXPECTED,
            "case {case} blocked for {elapsed:?}"
        );
    }
}

#[test]
fn slow_drip_does_not_renew_the_absolute_deadline() {
    let (mut sender, receiver) = UnixStream::pair().expect("transport pair");
    let sent = Arc::new(AtomicUsize::new(0));
    let sent_by_writer = Arc::clone(&sent);
    let drip = thread::spawn(move || {
        for byte in valid_frame() {
            if sender.write_all(&[byte]).is_err() {
                return;
            }
            sent_by_writer.fetch_add(1, Ordering::Relaxed);
            thread::sleep(Duration::from_millis(8));
        }
    });

    let budget = Duration::from_millis(55);
    let started = Instant::now();
    assert!(crate::writer_endpoint_handoff::receive_for_test(&receiver, budget).is_err());
    let elapsed = started.elapsed();
    drop(receiver);
    drip.join().expect("drip writer");
    assert!(
        sent.load(Ordering::Relaxed) < super::support::FRAME_BYTES,
        "slow drip reached the full frame and renewed the budget"
    );
    assert!(
        elapsed < MAX_EXPECTED,
        "slow drip renewed budget: {elapsed:?}"
    );
}

#[test]
fn non_socket_transport_fails_without_waiting_for_the_budget() {
    let file = std::fs::File::open("/dev/null").expect("open null");
    let started = Instant::now();
    assert!(crate::writer_endpoint_handoff::receive_for_test(&file, WATCHDOG).is_err());
    assert!(started.elapsed() < MAX_EXPECTED);
}
