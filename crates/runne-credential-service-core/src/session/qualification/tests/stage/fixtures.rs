use std::time::Instant;

use runne_api::CredentialServiceRegistrationBinding;
use runne_provider::{CredentialServiceEpoch, ServiceQualificationProtocolCodec};

use crate::session::qualification::{
    allocation::SystemQualificationAllocator,
    clocks::QualificationClockSource,
    resources::QualificationResourceBudget,
    stage::{CredentialServiceRuntimeStage, stage_qualification_request},
    state::QualificationState,
};

pub(super) struct FixedClock {
    pub(super) wall: u64,
    pub(super) monotonic: Instant,
}

impl QualificationClockSource for FixedClock {
    fn wall_unix_millis(&self) -> u64 {
        self.wall
    }

    fn monotonic_now(&self) -> Instant {
        self.monotonic
    }
}

pub(super) struct FixedEntropy;

impl super::super::super::stage::QualificationEntropySource for FixedEntropy {
    fn fill(&self, output: &mut [u8; 32]) -> Result<(), ()> {
        *output = [9; 32];
        Ok(())
    }
}

fn frame(kind: u8, sequence: u64, expires: u64, body: &[u8]) -> Vec<u8> {
    let body_len = u32::try_from(body.len()).expect("fixture body fits wire length");
    let mut bytes = vec![0_u8; 16 + 352 + body.len()];
    bytes[..8].copy_from_slice(b"RNQSVC01");
    bytes[8..10].copy_from_slice(&1_u16.to_be_bytes());
    bytes[10] = 1;
    bytes[11] = kind;
    bytes[12..16].copy_from_slice(&(352_u32 + body_len).to_be_bytes());
    let common = &mut bytes[16..368];
    common[..16].fill(1);
    common[16..32].fill(0);
    common[16] = 2;
    common[22] = 0x70;
    common[24] = 0x80;
    for offset in [32, 40, 48, 56, 144, 152, 200, 336, 344] {
        common[offset..offset + 8].copy_from_slice(&1_u64.to_be_bytes());
    }
    common[152..160].copy_from_slice(&10_000_u64.to_be_bytes());
    common[160..168].copy_from_slice(&sequence.to_be_bytes());
    common[64..96].fill(3);
    common[96..128].fill(4);
    common[128..144].fill(5);
    common[168..184].fill(6);
    common[184..200].fill(7);
    common[208..240].fill(8);
    common[240..272].fill(9);
    common[272..304].fill(10);
    common[304..336].fill(11);
    common[336..344].copy_from_slice(&100_u64.to_be_bytes());
    common[344..352].copy_from_slice(&expires.to_be_bytes());
    bytes[368..].copy_from_slice(body);
    bytes
}

pub(super) fn start_frame(sequence: u64, expires: u64) -> Vec<u8> {
    start_frame_with_transfer(sequence, expires, 13, 1)
}

pub(super) fn start_frame_with_transfer(
    sequence: u64,
    expires: u64,
    release_frame_len: u32,
    chunk_count: u16,
) -> Vec<u8> {
    let mut body = [0_u8; 12];
    body[..4].copy_from_slice(&release_frame_len.to_be_bytes());
    body[4..6].copy_from_slice(&8_192_u16.to_be_bytes());
    body[6..8].copy_from_slice(&chunk_count.to_be_bytes());
    body[8..12].copy_from_slice(&19_u32.to_be_bytes());
    frame(1, sequence, expires, &body)
}

pub(super) fn chunk_frame(sequence: u64, bytes: &[u8]) -> Vec<u8> {
    chunk_frame_part(sequence, 0, 1, 0, bytes)
}

pub(super) fn chunk_frame_part(
    sequence: u64,
    index: u16,
    count: u16,
    offset: u32,
    bytes: &[u8],
) -> Vec<u8> {
    let chunk_len = u16::try_from(bytes.len()).expect("fixture chunk fits wire length");
    let mut body = Vec::with_capacity(12 + bytes.len());
    body.extend_from_slice(&index.to_be_bytes());
    body.extend_from_slice(&count.to_be_bytes());
    body.extend_from_slice(&offset.to_be_bytes());
    body.extend_from_slice(&chunk_len.to_be_bytes());
    body.extend_from_slice(&0_u16.to_be_bytes());
    body.extend_from_slice(bytes);
    frame(2, sequence, 5_100, &body)
}

pub(super) fn finalize_frame(sequence: u64) -> Vec<u8> {
    let mut body = Vec::with_capacity(31);
    body.extend_from_slice(&13_u32.to_be_bytes());
    body.extend_from_slice(&1_u16.to_be_bytes());
    body.extend_from_slice(&0_u16.to_be_bytes());
    body.extend_from_slice(&19_u32.to_be_bytes());
    body.extend_from_slice(&[7; 19]);
    frame(3, sequence, 5_100, &body)
}

pub(super) fn registration() -> CredentialServiceRegistrationBinding {
    CredentialServiceRegistrationBinding::new(
        [1; 16],
        [2, 0, 0, 0, 0, 0, 0x70, 0, 0x80, 0, 0, 0, 0, 0, 0, 0],
        1,
        1,
        1,
        1,
        [3; 32],
        [4; 32],
        [5; 16],
        1,
        10_000,
    )
    .expect("fixture binding is valid")
}

pub(super) fn start_transfer(
    state: &mut QualificationState,
    sequence: &mut u64,
    budget: &QualificationResourceBudget,
    clock: &FixedClock,
) {
    let request = ServiceQualificationProtocolCodec::decode_request(&start_frame(1, 5_100))
        .expect("fixture is a typed Start request");
    let epoch = CredentialServiceEpoch::from_bytes([1; 16]).expect("fixture epoch");
    let transition = stage_qualification_request(
        state,
        sequence,
        &epoch,
        &registration(),
        request,
        budget,
        clock,
        &FixedEntropy,
    );
    let (outcome, retirement) = transition.into_parts();
    drop(retirement);
    let CredentialServiceRuntimeStage::AllocateQualification(pending) = outcome else {
        panic!("valid Start enters allocation")
    };
    let allocated = pending
        .allocate_with(&SystemQualificationAllocator)
        .unwrap_or_else(|_| panic!("small fixture allocation succeeds"));
    state
        .commit_allocation(allocated)
        .unwrap_or_else(|_| panic!("live allocation commits"));
}
