use std::io::Write as _;
use std::time::Duration;

use super::support::PrefixFixture;
use crate::MacOsPackagedWriterObservationError;
use crate::packaged_writer_observation::{
    test_only_heavy_capture_count, test_only_reset_heavy_capture_count,
};

const TEST_BUDGET: Duration = Duration::from_millis(70);

#[test]
fn invalid_attestation_rejects_before_deliberately_broken_package_evidence() {
    let mut fixture = PrefixFixture::new();
    fixture.attestation[577] ^= 0x80;
    fixture.control.write_all(&fixture.attestation).unwrap();
    test_only_reset_heavy_capture_count();

    assert!(matches!(
        fixture.observe_with_budget(TEST_BUDGET),
        Err(MacOsPackagedWriterObservationError::Rejected)
    ));
    assert_eq!(test_only_heavy_capture_count(), 0);
}

#[test]
fn valid_prefix_reaches_broken_package_only_after_all_three_items() {
    let mut fixture = PrefixFixture::new();
    fixture.write_prefix();
    test_only_reset_heavy_capture_count();

    assert!(matches!(
        fixture.observe_with_budget(TEST_BUDGET),
        Err(MacOsPackagedWriterObservationError::Rejected)
    ));
    assert_eq!(test_only_heavy_capture_count(), 1);
}

#[test]
fn prequeued_following_frame_is_rejected_before_heavy_capture() {
    let mut fixture = PrefixFixture::new();
    let mut bytes = fixture.prefix();
    bytes.push(0xa5);
    fixture.control.write_all(&bytes).unwrap();
    test_only_reset_heavy_capture_count();

    assert!(matches!(
        fixture.observe_with_budget(TEST_BUDGET),
        Err(MacOsPackagedWriterObservationError::Rejected)
    ));
    assert_eq!(test_only_heavy_capture_count(), 0);
}

#[test]
fn control_eof_after_prefix_is_rejected_before_heavy_capture() {
    let mut fixture = PrefixFixture::new();
    fixture.write_prefix();
    fixture.control.shutdown(std::net::Shutdown::Write).unwrap();
    test_only_reset_heavy_capture_count();

    assert!(matches!(
        fixture.observe_with_budget(TEST_BUDGET),
        Err(MacOsPackagedWriterObservationError::Rejected)
    ));
    assert_eq!(test_only_heavy_capture_count(), 0);
}

#[test]
fn slow_drip_exhausts_one_absolute_deadline_across_all_items() {
    let mut fixture = PrefixFixture::new();
    fixture.control.write_all(&fixture.attestation).unwrap();
    let mut control = fixture.control.try_clone().unwrap();
    let ticket = fixture.ticket.clone();
    let release = fixture.release.clone();
    let sender = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(45));
        let _ = control.write_all(&ticket);
        std::thread::sleep(Duration::from_millis(45));
        let _ = control.write_all(&release);
    });
    test_only_reset_heavy_capture_count();

    assert!(matches!(
        fixture.observe_with_budget(TEST_BUDGET),
        Err(MacOsPackagedWriterObservationError::Rejected)
    ));
    assert_eq!(test_only_heavy_capture_count(), 0);
    sender.join().unwrap();
}
