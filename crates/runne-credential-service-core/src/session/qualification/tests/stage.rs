use std::time::{Duration, Instant};

use runne_provider::{
    CredentialServiceEpoch, ServiceQualificationProtocolCodec, ServiceQualificationRejectionCode,
};

use crate::session::qualification::{
    resources::QualificationResourceBudget,
    retirement::DeferredQualificationRetirement,
    stage::{CredentialServiceRuntimeStage, stage_qualification_request},
    state::QualificationState,
};

mod chunk;
mod fixtures;
use fixtures::{
    FixedClock, FixedEntropy, chunk_frame, finalize_frame, registration, start_frame,
    start_transfer,
};

#[test]
fn typed_start_consumes_valid_sequence_before_allocating_outside_the_state_owner() {
    let request = ServiceQualificationProtocolCodec::decode_request(&start_frame(1, 5_100))
        .expect("fixture is a typed Start request");
    let epoch = CredentialServiceEpoch::from_bytes([1; 16]).expect("fixture epoch");
    let mut state = QualificationState::empty();
    let mut last_sequence = 0;
    let budget = QualificationResourceBudget::new_for_test();
    let clock = FixedClock {
        wall: 100,
        monotonic: Instant::now(),
    };
    let transition = stage_qualification_request(
        &mut state,
        &mut last_sequence,
        &epoch,
        &registration(),
        request,
        &budget,
        &clock,
        &FixedEntropy,
    );
    let (outcome, retirement) = transition.into_parts();
    assert!(matches!(
        outcome,
        CredentialServiceRuntimeStage::AllocateQualification(_)
    ));
    drop(retirement);
    assert_eq!(last_sequence, 1);
    assert_eq!(budget.usage_for_test(), (1, 32, 0));
}

#[test]
fn typed_chunk_assembles_contiguously_then_finalize_moves_complete_pending_owner() {
    let base = Instant::now();
    let clock = FixedClock {
        wall: 100,
        monotonic: base,
    };
    let budget = QualificationResourceBudget::new_for_test();
    let mut state = QualificationState::empty();
    let mut sequence = 0;
    start_transfer(&mut state, &mut sequence, &budget, &clock);

    let epoch = CredentialServiceEpoch::from_bytes([1; 16]).unwrap();
    let chunk = ServiceQualificationProtocolCodec::decode_request(&chunk_frame(2, &[4; 13]))
        .expect("fixture is a typed Chunk request");
    let progress = stage_qualification_request(
        &mut state,
        &mut sequence,
        &epoch,
        &registration(),
        chunk,
        &budget,
        &clock,
        &FixedEntropy,
    );
    let (progress, retirement) = progress.into_parts();
    assert!(matches!(
        progress,
        CredentialServiceRuntimeStage::Progress {
            next_chunk_index: 1,
            received_release_bytes: 13,
            ..
        }
    ));
    drop(retirement);

    let finalize = ServiceQualificationProtocolCodec::decode_request(&finalize_frame(3))
        .expect("fixture is a typed Finalize request");
    let transition = stage_qualification_request(
        &mut state,
        &mut sequence,
        &epoch,
        &registration(),
        finalize,
        &budget,
        &clock,
        &FixedEntropy,
    );
    let (outcome, retirement) = transition.into_parts();
    let CredentialServiceRuntimeStage::VerifyQualification(pending) = outcome else {
        panic!("complete transfer enters verification staging")
    };
    assert_eq!(budget.usage_for_test(), (1, 32, 1));
    drop(retirement);
    drop(state.abort_finalize(pending));
    assert_eq!(budget.usage_for_test(), (0, 0, 0));
}

#[test]
fn state_invalid_chunk_consumes_sequence_and_retires_owned_chunk_bytes() {
    let request = ServiceQualificationProtocolCodec::decode_request(&chunk_frame(1, &[4; 13]))
        .expect("fixture is a typed Chunk request");
    let epoch = CredentialServiceEpoch::from_bytes([1; 16]).unwrap();
    let mut state = QualificationState::empty();
    let mut sequence = 0;
    let budget = QualificationResourceBudget::new_for_test();
    let clock = FixedClock {
        wall: 100,
        monotonic: Instant::now(),
    };
    let transition = stage_qualification_request(
        &mut state,
        &mut sequence,
        &epoch,
        &registration(),
        request,
        &budget,
        &clock,
        &FixedEntropy,
    );
    let (outcome, retirement) = transition.into_parts();
    assert!(matches!(
        outcome,
        CredentialServiceRuntimeStage::Reply {
            kind: runne_provider::ServiceQualificationRequestKind::Chunk,
            sequence: 1,
            code: ServiceQualificationRejectionCode::Denied,
        }
    ));
    assert_eq!(sequence, 1);
    drop(retirement);
}

#[test]
fn pre_context_chunk_rejection_defers_payload_drop() {
    let mut frame = chunk_frame(1, &[4; 13]);
    frame[16 + 64] = 99;
    let request = ServiceQualificationProtocolCodec::decode_request(&frame)
        .expect("fixture remains syntactically valid");
    let epoch = CredentialServiceEpoch::from_bytes([1; 16]).unwrap();
    let mut state = QualificationState::empty();
    let mut sequence = 0;
    let budget = QualificationResourceBudget::new_for_test();
    let clock = FixedClock {
        wall: 100,
        monotonic: Instant::now(),
    };

    let (_, retirement) = stage_qualification_request(
        &mut state,
        &mut sequence,
        &epoch,
        &registration(),
        request,
        &budget,
        &clock,
        &FixedEntropy,
    )
    .into_parts();

    assert!(matches!(
        retirement,
        DeferredQualificationRetirement::Payload(_)
    ));
    assert_eq!(sequence, 0);
}

#[test]
fn capacity_rejection_consumes_sequence_without_queueing() {
    let budget = QualificationResourceBudget::new_for_test();
    let held: Vec<_> = (0..8)
        .map(|_| budget.try_acquire_reservation_for_test(1).unwrap())
        .collect();
    let request =
        ServiceQualificationProtocolCodec::decode_request(&start_frame(1, 5_100)).unwrap();
    let epoch = CredentialServiceEpoch::from_bytes([1; 16]).unwrap();
    let mut state = QualificationState::empty();
    let mut sequence = 0;
    let clock = FixedClock {
        wall: 100,
        monotonic: Instant::now(),
    };
    let transition = stage_qualification_request(
        &mut state,
        &mut sequence,
        &epoch,
        &registration(),
        request,
        &budget,
        &clock,
        &FixedEntropy,
    );
    let (outcome, retirement) = transition.into_parts();
    assert!(matches!(
        outcome,
        CredentialServiceRuntimeStage::Reply {
            code: ServiceQualificationRejectionCode::Busy,
            ..
        }
    ));
    drop(retirement);
    assert_eq!(sequence, 1);
    drop(held);
}

#[test]
fn expired_monotonic_transfer_detaches_buffers_after_sequence_consumption() {
    let base = Instant::now();
    let start_clock = FixedClock {
        wall: 100,
        monotonic: base,
    };
    let budget = QualificationResourceBudget::new_for_test();
    let mut state = QualificationState::empty();
    let mut sequence = 0;
    start_transfer(&mut state, &mut sequence, &budget, &start_clock);
    let request =
        ServiceQualificationProtocolCodec::decode_request(&chunk_frame(2, &[4; 13])).unwrap();
    let epoch = CredentialServiceEpoch::from_bytes([1; 16]).unwrap();
    let expired_clock = FixedClock {
        wall: 100,
        monotonic: base + Duration::from_secs(5),
    };
    let transition = stage_qualification_request(
        &mut state,
        &mut sequence,
        &epoch,
        &registration(),
        request,
        &budget,
        &expired_clock,
        &FixedEntropy,
    );
    let (outcome, retirement) = transition.into_parts();
    assert!(matches!(
        outcome,
        CredentialServiceRuntimeStage::Reply {
            code: ServiceQualificationRejectionCode::Expired,
            ..
        }
    ));
    assert_eq!(sequence, 2);
    assert_eq!(budget.usage_for_test(), (1, 32, 0));
    drop(retirement);
    assert_eq!(budget.usage_for_test(), (0, 0, 0));
}

#[test]
fn binding_or_freshness_failure_does_not_advance_sequence() {
    let mut future = start_frame(1, 5_100);
    future[16 + 336..16 + 344].copy_from_slice(&101_u64.to_be_bytes());
    let request = ServiceQualificationProtocolCodec::decode_request(&future).unwrap();
    let epoch = CredentialServiceEpoch::from_bytes([1; 16]).unwrap();
    let mut state = QualificationState::empty();
    let mut sequence = 0;
    let budget = QualificationResourceBudget::new_for_test();
    let clock = FixedClock {
        wall: 100,
        monotonic: Instant::now(),
    };
    let transition = stage_qualification_request(
        &mut state,
        &mut sequence,
        &epoch,
        &registration(),
        request,
        &budget,
        &clock,
        &FixedEntropy,
    );
    let (outcome, retirement) = transition.into_parts();
    assert!(matches!(
        outcome,
        CredentialServiceRuntimeStage::Reply {
            code: ServiceQualificationRejectionCode::Expired,
            ..
        }
    ));
    drop(retirement);
    assert_eq!(sequence, 0);
}
