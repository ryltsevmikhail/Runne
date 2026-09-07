use super::{task_2b3c_request, task_2b3c_start_body};
use crate::credential::enrollment::service_qualification_protocol::{
    ServiceQualificationProtocolCodec, ServiceQualificationRejectionCode,
};

fn chunk_count(release: u32) -> u16 {
    ((release - 1) / 8192 + 1) as u16
}

fn chunk_body(index: u16, count: u16, length: u16) -> Vec<u8> {
    let mut body = Vec::with_capacity(12 + usize::from(length));
    body.extend_from_slice(&index.to_be_bytes());
    body.extend_from_slice(&count.to_be_bytes());
    body.extend_from_slice(&(u32::from(index) * 8192).to_be_bytes());
    body.extend_from_slice(&length.to_be_bytes());
    body.extend_from_slice(&0_u16.to_be_bytes());
    body.extend(std::iter::repeat_n(1, usize::from(length)));
    body
}

fn finalize_body(release: u32, admission: u32) -> Vec<u8> {
    let mut body = Vec::with_capacity(12 + admission as usize);
    body.extend_from_slice(&release.to_be_bytes());
    body.extend_from_slice(&chunk_count(release).to_be_bytes());
    body.extend_from_slice(&0_u16.to_be_bytes());
    body.extend_from_slice(&admission.to_be_bytes());
    body.extend(std::iter::repeat_n(2, admission as usize));
    body
}

fn decode(kind: u8, body: &[u8]) -> bool {
    ServiceQualificationProtocolCodec::decode_request(&task_2b3c_request(kind, body)).is_ok()
}

#[test]
fn task_2b3c_rejects_request_truncation_bad_magic_and_declared_length() {
    let frame = task_2b3c_request(1, &task_2b3c_start_body(13, 1, 19));
    for length in 0..frame.len() {
        assert!(ServiceQualificationProtocolCodec::decode_request(&frame[..length]).is_err());
    }
    for (offset, value) in [(0, b'X'), (15, 0)] {
        let mut malformed = frame.clone();
        malformed[offset] = value;
        assert!(ServiceQualificationProtocolCodec::decode_request(&malformed).is_err());
    }
}

#[test]
fn task_2b3c_rejects_each_zero_common_fact_and_bad_session_uuid_bits() {
    let frame = task_2b3c_request(1, &task_2b3c_start_body(13, 1, 19));
    for (offset, width) in [
        (0, 16),
        (16, 16),
        (32, 8),
        (40, 8),
        (48, 8),
        (56, 8),
        (64, 32),
        (96, 32),
        (128, 16),
        (144, 8),
        (152, 8),
        (160, 8),
        (168, 16),
        (184, 16),
        (200, 8),
        (208, 32),
        (240, 32),
        (272, 32),
        (304, 32),
        (336, 8),
        (344, 8),
    ] {
        let mut malformed = frame.clone();
        malformed[16 + offset..16 + offset + width].fill(0);
        assert!(ServiceQualificationProtocolCodec::decode_request(&malformed).is_err());
    }
    for offset in [22, 24] {
        let mut malformed = frame.clone();
        malformed[16 + offset] = 1;
        assert!(ServiceQualificationProtocolCodec::decode_request(&malformed).is_err());
    }
}

#[test]
fn task_2b3c_accepts_and_rejects_exact_release_and_admission_boundaries() {
    for release in [13, 8192, 8193, 524_288, 524_300] {
        assert!(decode(
            1,
            &task_2b3c_start_body(release, chunk_count(release), 19)
        ));
        assert!(decode(3, &finalize_body(release, 8192)));
    }
    for admission in [18, 8193] {
        assert!(!decode(1, &task_2b3c_start_body(13, 1, admission)));
        assert!(!decode(3, &finalize_body(13, admission)));
    }
    assert!(!decode(1, &task_2b3c_start_body(524_301, 65, 19)));
    assert!(!decode(3, &finalize_body(524_301, 19)));
}

#[test]
fn task_2b3c_accepts_only_possible_final_chunk_remainders() {
    for (count, index, length, accepted) in [
        (1, 0, 13, true),
        (1, 0, 8192, true),
        (2, 0, 8192, true),
        (65, 64, 12, true),
        (1, 0, 12, false),
        (65, 64, 13, false),
        (65, 64, 8192, false),
    ] {
        assert_eq!(decode(2, &chunk_body(index, count, length)), accepted);
    }
}

#[test]
fn task_2b3c_encodes_both_progress_kinds_and_rejections() {
    let start = ServiceQualificationProtocolCodec::decode_request(&task_2b3c_request(
        1,
        &task_2b3c_start_body(13, 1, 19),
    ))
    .unwrap();
    let progress = ServiceQualificationProtocolCodec::encode_progress(start, 1, 13).unwrap();
    assert_eq!(progress.test_bytes()[11], 0x81);
    let chunk = ServiceQualificationProtocolCodec::decode_request(&task_2b3c_request(
        2,
        &chunk_body(0, 1, 13),
    ))
    .unwrap();
    let progress = ServiceQualificationProtocolCodec::encode_progress(chunk, 1, 13).unwrap();
    assert_eq!(progress.test_bytes()[11], 0x82);
    let codes = [
        (ServiceQualificationRejectionCode::Denied, 1),
        (ServiceQualificationRejectionCode::Busy, 2),
        (ServiceQualificationRejectionCode::Expired, 3),
        (ServiceQualificationRejectionCode::Unavailable, 4),
    ];
    for kind in [1, 2, 3] {
        let body = match kind {
            1 => task_2b3c_start_body(13, 1, 19).to_vec(),
            2 => chunk_body(0, 1, 13),
            _ => finalize_body(13, 19),
        };
        for (code, wire_code) in codes {
            let request =
                ServiceQualificationProtocolCodec::decode_request(&task_2b3c_request(kind, &body))
                    .unwrap();
            let rejection = ServiceQualificationProtocolCodec::encode_rejected(request, code);
            assert_eq!(&rejection.test_bytes()[368..], &[kind, wire_code, 0, 0]);
        }
    }
}
