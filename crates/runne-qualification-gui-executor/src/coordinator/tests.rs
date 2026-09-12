use std::sync::Arc;
use std::time::{Duration, Instant};

use runne_api::{DesktopOfferRequest, RootPrepared, RunBinding, RuntimeBootstrapRequest};

use super::RunCoordinator;

fn binding() -> RunBinding {
    RunBinding::new(
        "run-42", [1; 20], [2; 32], [3; 32], [4; 32], [5; 32], [6; 32],
    )
    .unwrap()
}

fn coordinator() -> RunCoordinator {
    RunCoordinator::new(
        RootPrepared::new([7; 32], binding(), 100, 200).unwrap(),
        Instant::now() + Duration::from_secs(1),
    )
}

#[test]
fn runtime_needs_one_successful_desktop_offer() {
    let premature = coordinator();
    let started = Instant::now();
    assert!(premature.claim_runtime().is_err());
    assert!(started.elapsed() < Duration::from_millis(20));
    premature.opened().unwrap();

    let coordinator = coordinator();
    coordinator.opened().unwrap();
    coordinator.claim_desktop().unwrap();
    let offer = coordinator
        .desktop_offer(&DesktopOfferRequest::new([8; 32]).unwrap())
        .unwrap();
    assert_eq!(offer.desktop_challenge(), [8; 32]);
    coordinator.finish_desktop().unwrap();
    assert!(coordinator.claim_runtime().is_ok());
    assert!(coordinator.claim_runtime().is_err());
}

#[test]
fn desktop_reservation_is_prompt_and_its_exchange_waits_for_open() {
    let coordinator = Arc::new(coordinator());
    let started = Instant::now();
    coordinator.claim_desktop().unwrap();
    assert!(started.elapsed() < Duration::from_millis(20));

    let waiting = Arc::clone(&coordinator);
    let exchange = std::thread::spawn(move || {
        waiting.desktop_offer(&DesktopOfferRequest::new([8; 32]).unwrap())
    });
    std::thread::sleep(Duration::from_millis(10));
    coordinator.opened().unwrap();
    assert!(exchange.join().unwrap().is_ok());
}

#[test]
fn opening_failure_and_timeout_release_waiting_desktop_exchange() {
    let coordinator = Arc::new(coordinator());
    coordinator.claim_desktop().unwrap();
    let waiting = Arc::clone(&coordinator);
    let exchange = std::thread::spawn(move || {
        waiting.desktop_offer(&DesktopOfferRequest::new([8; 32]).unwrap())
    });
    std::thread::sleep(Duration::from_millis(10));
    coordinator.fail();
    assert!(exchange.join().unwrap().is_err());

    let timeout = RunCoordinator::new(
        RootPrepared::new([7; 32], binding(), 100, 200).unwrap(),
        Instant::now() + Duration::from_millis(20),
    );
    timeout.claim_desktop().unwrap();
    assert!(
        timeout
            .desktop_offer(&DesktopOfferRequest::new([8; 32]).unwrap())
            .is_err()
    );
}

#[test]
fn mismatched_runtime_digests_do_not_match_prepared_offer() {
    let coordinator = coordinator();
    coordinator.opened().unwrap();
    coordinator.claim_desktop().unwrap();
    let _ = coordinator
        .desktop_offer(&DesktopOfferRequest::new([8; 32]).unwrap())
        .unwrap();
    coordinator.finish_desktop().unwrap();
    let ticket = coordinator.claim_runtime().unwrap();
    let request =
        RuntimeBootstrapRequest::new([7; 32], [9; 32], [2; 32], [3; 32], [10; 32]).unwrap();
    assert!(!ticket.matches(&request));
}
