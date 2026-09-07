use std::time::Instant;

use runne_provider::{CredentialServiceEpoch, ServiceQualificationProtocolCodec};
use zeroize::Zeroizing;

use crate::session::qualification::{
    allocation::SystemQualificationAllocator,
    binding::QualificationBinding,
    resources::QualificationResourceBudget,
    stage::{CredentialServiceRuntimeStage, stage_qualification_request},
    state::QualificationState,
    transfer::{QualificationChunk, QualificationTransferRejection},
};

use super::fixtures::{FixedClock, FixedEntropy, registration, start_frame_with_transfer};

#[test]
fn short_nonfinal_chunk_is_rejected_and_retires_the_live_transfer() {
    let clock = FixedClock {
        wall: 100,
        monotonic: Instant::now(),
    };
    let budget = QualificationResourceBudget::new_for_test();
    let epoch = CredentialServiceEpoch::from_bytes([1; 16]).unwrap();
    let mut state = QualificationState::empty();
    let mut sequence = 0;
    let start = ServiceQualificationProtocolCodec::decode_request(&start_frame_with_transfer(
        1, 5_100, 8_193, 2,
    ))
    .unwrap();
    let (transition, retirement) = stage_qualification_request(
        &mut state,
        &mut sequence,
        &epoch,
        &registration(),
        start,
        &budget,
        &clock,
        &FixedEntropy,
    )
    .into_parts();
    drop(retirement);
    let CredentialServiceRuntimeStage::AllocateQualification(pending) = transition else {
        panic!("two-chunk Start enters allocation")
    };
    let allocated = pending
        .allocate_with(&SystemQualificationAllocator)
        .unwrap_or_else(|_| panic!("bounded test allocation succeeds"));
    state
        .commit_allocation(allocated)
        .unwrap_or_else(|_| panic!("allocation commits"));

    let binding_request = ServiceQualificationProtocolCodec::decode_request(
        &start_frame_with_transfer(1, 5_100, 8_193, 2),
    )
    .unwrap();
    let (common, _) = binding_request.into_parts();
    let binding = QualificationBinding::from_common(&common);
    let failure = match state.accept_chunk(
        &binding,
        QualificationChunk {
            index: 0,
            count: 2,
            offset: 0,
            bytes: Zeroizing::new(vec![4; 13]),
        },
        clock.monotonic,
    ) {
        Err(failure) => failure,
        Ok((_, retirement)) => {
            drop(retirement);
            panic!("a nonfinal chunk must fill its fixed-size wire slot");
        }
    };
    assert!(matches!(
        failure.reason,
        QualificationTransferRejection::Denied
    ));
    assert_eq!(budget.usage_for_test(), (1, 8_212, 0));
    drop(failure.retirement);
    assert_eq!(budget.usage_for_test(), (0, 0, 0));
}
