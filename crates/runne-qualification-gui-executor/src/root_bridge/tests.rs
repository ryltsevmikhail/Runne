use std::time::{Duration, Instant};

use runne_api::{BootstrapAck, RootIssuedProof, RunBinding};
use sha2::{Digest as _, Sha256};

use crate::coordinator::RunCoordinator;

use super::{ack_matches, consume_plan};

fn binding() -> RunBinding {
    RunBinding::new(
        "run-42", [1; 20], [2; 32], [3; 32], [4; 32], [5; 32], [6; 32],
    )
    .unwrap()
}

fn ticket() -> crate::coordinator::RuntimeTicket {
    let coordinator = RunCoordinator::new(
        runne_api::RootPrepared::new([7; 32], binding(), 100, 200).unwrap(),
        Instant::now() + Duration::from_secs(1),
    );
    coordinator.opened().unwrap();
    coordinator.claim_desktop().unwrap();
    let _ = coordinator
        .desktop_offer(&runne_api::DesktopOfferRequest::new([8; 32]).unwrap())
        .unwrap();
    coordinator.finish_desktop().unwrap();
    coordinator.claim_runtime().unwrap()
}

#[test]
fn wrong_root_issued_proof_cannot_create_a_root_consume_request() {
    let issued = RootIssuedProof::new([8; 32], [9; 32], vec![1]).unwrap();
    assert!(consume_plan(issued, &ticket(), [9; 32]).is_err());
}

#[test]
fn acknowledgement_requires_exact_offer_challenge_digest_and_binding() {
    let ticket = ticket();
    let proof = vec![1, 2, 3];
    let digest: [u8; 32] = Sha256::digest(&proof).into();
    let good = BootstrapAck::new([7; 32], [9; 32], binding(), digest, 200).unwrap();
    assert!(ack_matches(&good, &ticket, [9; 32], digest));

    let wrong_challenge = BootstrapAck::new([7; 32], [10; 32], binding(), digest, 200).unwrap();
    assert!(!ack_matches(&wrong_challenge, &ticket, [9; 32], digest));
    assert!(!ack_matches(&good, &ticket, [9; 32], [11; 32]));

    let other = RunBinding::new(
        "run-42", [1; 20], [2; 32], [3; 32], [4; 32], [12; 32], [6; 32],
    )
    .unwrap();
    let wrong_binding = BootstrapAck::new([7; 32], [9; 32], other, digest, 200).unwrap();
    assert!(!ack_matches(&wrong_binding, &ticket, [9; 32], digest));
}
