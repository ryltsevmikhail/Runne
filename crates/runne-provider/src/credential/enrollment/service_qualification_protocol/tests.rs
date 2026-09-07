use super::{
    ServiceQualificationCommon, ServiceQualificationProtocolCodec,
    ServiceQualificationRejectionCode, ServiceQualificationReplyFrame, ServiceQualificationRequest,
    ServiceQualificationRequestPayload,
};
use static_assertions::assert_not_impl_any;
use std::fmt::Debug;

pub(super) fn task_2b3c_common() -> Vec<u8> {
    let mut common = Vec::with_capacity(352);
    common.extend_from_slice(&[1; 16]);
    common.extend_from_slice(&[1, 1, 1, 1, 1, 1, 0x70, 1, 0x80, 1, 1, 1, 1, 1, 1, 2]);
    for value in [1_u64, 2, 3, 4] {
        common.extend_from_slice(&value.to_be_bytes());
    }
    common.extend_from_slice(&[2; 32]);
    common.extend_from_slice(&[3; 32]);
    common.extend_from_slice(&[4; 16]);
    for value in [5_u64, 200, 300] {
        common.extend_from_slice(&value.to_be_bytes());
    }
    for value in [[5; 16], [6; 16]] {
        common.extend_from_slice(&value);
    }
    common.extend_from_slice(&7_u64.to_be_bytes());
    for value in [[7; 32], [8; 32], [9; 32], [10; 32]] {
        common.extend_from_slice(&value);
    }
    common.extend_from_slice(&100_u64.to_be_bytes());
    common.extend_from_slice(&101_u64.to_be_bytes());
    assert_eq!(common.len(), 352);
    common
}

pub(super) fn task_2b3c_request(kind: u8, body: &[u8]) -> Vec<u8> {
    let mut payload = task_2b3c_common();
    payload.extend_from_slice(body);
    let mut frame = Vec::with_capacity(16 + payload.len());
    frame.extend_from_slice(b"RNQSVC01");
    frame.extend_from_slice(&1_u16.to_be_bytes());
    frame.push(1);
    frame.push(kind);
    frame.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    frame.extend_from_slice(&payload);
    frame
}

pub(super) fn task_2b3c_start_body(release: u32, count: u16, admission: u32) -> [u8; 12] {
    let mut body = [0; 12];
    body[..4].copy_from_slice(&release.to_be_bytes());
    body[4..6].copy_from_slice(&8192_u16.to_be_bytes());
    body[6..8].copy_from_slice(&count.to_be_bytes());
    body[8..].copy_from_slice(&admission.to_be_bytes());
    body
}

#[test]
fn task_2b3c_rejects_short_nonfinal_chunk_body() {
    let mut body = Vec::new();
    body.extend_from_slice(&0_u16.to_be_bytes());
    body.extend_from_slice(&2_u16.to_be_bytes());
    body.extend_from_slice(&0_u32.to_be_bytes());
    body.extend_from_slice(&1_u16.to_be_bytes());
    body.extend_from_slice(&0_u16.to_be_bytes());
    body.push(7);

    assert!(
        ServiceQualificationProtocolCodec::decode_request(&task_2b3c_request(2, &body)).is_err()
    );
}

#[test]
fn task_2b3c_rejects_header_and_common_binding_mutations() {
    let body = task_2b3c_start_body(13, 1, 19);
    let frame = task_2b3c_request(1, &body);
    let mutations = [(8, 2), (10, 2), (11, 4), (38, 0), (40, 0)];

    for (offset, value) in mutations {
        let mut invalid = frame.clone();
        invalid[offset] = value;
        assert!(ServiceQualificationProtocolCodec::decode_request(&invalid).is_err());
    }
    let mut zero_epoch = frame.clone();
    zero_epoch[16..32].fill(0);
    assert!(ServiceQualificationProtocolCodec::decode_request(&zero_epoch).is_err());
    let mut trailing = frame;
    trailing.push(0);
    assert!(ServiceQualificationProtocolCodec::decode_request(&trailing).is_err());
}

#[test]
fn task_2b3c_rejects_inconsistent_start_and_finalize_scalars() {
    let invalid_start = task_2b3c_start_body(8_193, 1, 19);
    assert!(
        ServiceQualificationProtocolCodec::decode_request(&task_2b3c_request(1, &invalid_start))
            .is_err()
    );

    let mut final_body = Vec::new();
    final_body.extend_from_slice(&8_193_u32.to_be_bytes());
    final_body.extend_from_slice(&1_u16.to_be_bytes());
    final_body.extend_from_slice(&0_u16.to_be_bytes());
    final_body.extend_from_slice(&19_u32.to_be_bytes());
    final_body.extend_from_slice(&[7; 19]);
    assert!(
        ServiceQualificationProtocolCodec::decode_request(&task_2b3c_request(3, &final_body))
            .is_err()
    );
}

#[test]
fn task_2b3c_accepts_exact_maximum_start_chunk_and_finalize_frames() {
    let start = task_2b3c_start_body(524_300, 65, 8_192);
    assert!(
        ServiceQualificationProtocolCodec::decode_request(&task_2b3c_request(1, &start)).is_ok()
    );

    let mut chunk = Vec::new();
    chunk.extend_from_slice(&0_u16.to_be_bytes());
    chunk.extend_from_slice(&65_u16.to_be_bytes());
    chunk.extend_from_slice(&0_u32.to_be_bytes());
    chunk.extend_from_slice(&8192_u16.to_be_bytes());
    chunk.extend_from_slice(&0_u16.to_be_bytes());
    chunk.extend_from_slice(&[1; 8192]);
    assert!(
        ServiceQualificationProtocolCodec::decode_request(&task_2b3c_request(2, &chunk)).is_ok()
    );

    let mut finalize = Vec::new();
    finalize.extend_from_slice(&524_300_u32.to_be_bytes());
    finalize.extend_from_slice(&65_u16.to_be_bytes());
    finalize.extend_from_slice(&0_u16.to_be_bytes());
    finalize.extend_from_slice(&8192_u32.to_be_bytes());
    finalize.extend_from_slice(&[2; 8192]);
    assert!(
        ServiceQualificationProtocolCodec::decode_request(&task_2b3c_request(3, &finalize)).is_ok()
    );
}

#[test]
fn task_2b3c_rejects_chunk_reserved_offset_and_overlong_body() {
    let mut body = Vec::new();
    body.extend_from_slice(&1_u16.to_be_bytes());
    body.extend_from_slice(&2_u16.to_be_bytes());
    body.extend_from_slice(&8192_u32.to_be_bytes());
    body.extend_from_slice(&8192_u16.to_be_bytes());
    body.extend_from_slice(&0_u16.to_be_bytes());
    body.extend_from_slice(&[1; 8192]);
    assert!(
        ServiceQualificationProtocolCodec::decode_request(&task_2b3c_request(2, &body)).is_ok()
    );

    let mut reserved = body.clone();
    reserved[10] = 1;
    assert!(
        ServiceQualificationProtocolCodec::decode_request(&task_2b3c_request(2, &reserved))
            .is_err()
    );
    let mut offset = body.clone();
    offset[4] = 1;
    assert!(
        ServiceQualificationProtocolCodec::decode_request(&task_2b3c_request(2, &offset)).is_err()
    );
    let mut trailing = body;
    trailing.push(0);
    assert!(
        ServiceQualificationProtocolCodec::decode_request(&task_2b3c_request(2, &trailing))
            .is_err()
    );
}

#[test]
fn task_2b3c_encodes_exact_nonfinal_progress_and_rejection() {
    let body = task_2b3c_start_body(13, 1, 19);
    let request =
        ServiceQualificationProtocolCodec::decode_request(&task_2b3c_request(1, &body)).unwrap();
    let progress = ServiceQualificationProtocolCodec::encode_progress(request, 1, 13).unwrap();
    let bytes = progress.test_bytes();
    assert_eq!(bytes.len(), 376);
    assert_eq!(&bytes[..16], b"RNQSVC01\0\x01\x02\x81\0\0\x01\x68");
    assert_eq!(&bytes[368..], &[0, 1, 0, 0, 0, 0, 0, 13]);

    let request =
        ServiceQualificationProtocolCodec::decode_request(&task_2b3c_request(1, &body)).unwrap();
    let rejection = ServiceQualificationProtocolCodec::encode_rejected(
        request,
        ServiceQualificationRejectionCode::Busy,
    );
    let bytes = rejection.test_bytes();
    assert_eq!(bytes.len(), 372);
    assert_eq!(&bytes[..16], b"RNQSVC01\0\x01\x02\xff\0\0\x01\x64");
    assert_eq!(&bytes[368..], &[1, 2, 0, 0]);
}

#[test]
fn task_2b3c_keeps_qualification_frames_move_only() {
    assert_not_impl_any!(ServiceQualificationRequest: Clone, Copy, Debug);
    assert_not_impl_any!(ServiceQualificationReplyFrame: Clone, Copy, Debug);
    assert_not_impl_any!(ServiceQualificationCommon: Clone, Copy, Debug);
    assert_not_impl_any!(ServiceQualificationRequestPayload: Clone, Copy, Debug);
}

#[test]
fn task_2b3c_retains_typed_start_chunk_and_finalize_payloads() {
    let start = ServiceQualificationProtocolCodec::decode_request(&task_2b3c_request(
        1,
        &task_2b3c_start_body(13, 1, 19),
    ))
    .unwrap();
    let (common, payload) = start.into_parts();
    assert_eq!(common.sequence, 300);
    assert!(matches!(
        payload,
        ServiceQualificationRequestPayload::Start {
            release_frame_len: 13,
            chunk_bytes: 8192,
            chunk_count: 1,
            admission_bundle_len: 19,
        }
    ));

    let chunk = ServiceQualificationProtocolCodec::decode_request(&task_2b3c_request(
        2,
        &[
            0, 0, 0, 1, 0, 0, 0, 0, 0, 13, 0, 0, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19,
        ],
    ))
    .unwrap();
    assert!(matches!(
        chunk.into_parts().1,
        ServiceQualificationRequestPayload::Chunk {
            chunk_index: 0,
            chunk_count: 1,
            offset: 0,
            bytes,
        } if bytes.as_slice() == [7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19]
    ));

    let finalize = ServiceQualificationProtocolCodec::decode_request(&task_2b3c_request(
        3,
        &[
            0, 0, 0, 13, 0, 1, 0, 0, 0, 0, 0, 19, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
            17, 18, 19, 20, 21,
        ],
    ))
    .unwrap();
    assert!(matches!(
        finalize.into_parts().1,
        ServiceQualificationRequestPayload::Finalize {
            release_frame_len: 13,
            chunk_count: 1,
            admission_bundle,
        } if admission_bundle.as_slice() == [3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21]
    ));
}

#[test]
fn task_2b3c_rejects_impossible_final_chunk_lengths() {
    for (count, index, length) in [(1_u16, 0_u16, 1_u16), (65, 64, 8192)] {
        let mut body = Vec::new();
        body.extend_from_slice(&index.to_be_bytes());
        body.extend_from_slice(&count.to_be_bytes());
        body.extend_from_slice(&(u32::from(index) * 8192).to_be_bytes());
        body.extend_from_slice(&length.to_be_bytes());
        body.extend_from_slice(&0_u16.to_be_bytes());
        body.extend(std::iter::repeat_n(1, usize::from(length)));
        assert!(
            ServiceQualificationProtocolCodec::decode_request(&task_2b3c_request(2, &body))
                .is_err()
        );
    }
}

#[test]
fn task_2b3c_accepts_the_65_chunk_final_remainder() {
    let mut body = Vec::new();
    body.extend_from_slice(&64_u16.to_be_bytes());
    body.extend_from_slice(&65_u16.to_be_bytes());
    body.extend_from_slice(&524_288_u32.to_be_bytes());
    body.extend_from_slice(&12_u16.to_be_bytes());
    body.extend_from_slice(&0_u16.to_be_bytes());
    body.extend_from_slice(&[1; 12]);
    assert!(
        ServiceQualificationProtocolCodec::decode_request(&task_2b3c_request(2, &body)).is_ok()
    );
}

mod matrix;
