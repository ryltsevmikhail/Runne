use runne_provider::{
    ServiceQualificationCommon, ServiceQualificationProtocolCodec,
    ServiceQualificationRejectionCode, ServiceQualificationReplyFrame,
    ServiceQualificationRequestKind, ServiceQualificationRequestPayload,
};

fn accepts_public_reply_type(_: ServiceQualificationReplyFrame) {}

fn task_2b3c_start_frame() -> Vec<u8> {
    let mut frame = Vec::with_capacity(380);
    frame.extend_from_slice(b"RNQSVC01");
    frame.extend_from_slice(&1_u16.to_be_bytes());
    frame.push(1);
    frame.push(1);
    frame.extend_from_slice(&364_u32.to_be_bytes());
    frame.extend_from_slice(&[1; 16]);
    frame.extend_from_slice(&[1, 1, 1, 1, 1, 1, 0x70, 1, 0x80, 1, 1, 1, 1, 1, 1, 2]);
    for value in [1_u64, 2, 3, 4] {
        frame.extend_from_slice(&value.to_be_bytes());
    }
    frame.extend_from_slice(&[2; 32]);
    frame.extend_from_slice(&[3; 32]);
    frame.extend_from_slice(&[4; 16]);
    for value in [5_u64, 200, 300] {
        frame.extend_from_slice(&value.to_be_bytes());
    }
    for value in [[5; 16], [6; 16]] {
        frame.extend_from_slice(&value);
    }
    frame.extend_from_slice(&7_u64.to_be_bytes());
    for value in [[7; 32], [8; 32], [9; 32], [10; 32]] {
        frame.extend_from_slice(&value);
    }
    frame.extend_from_slice(&100_u64.to_be_bytes());
    frame.extend_from_slice(&101_u64.to_be_bytes());
    frame.extend_from_slice(&13_u32.to_be_bytes());
    frame.extend_from_slice(&8192_u16.to_be_bytes());
    frame.extend_from_slice(&1_u16.to_be_bytes());
    frame.extend_from_slice(&19_u32.to_be_bytes());
    frame
}

#[test]
fn task_2b3c_accepts_exact_start_layout() {
    let request = ServiceQualificationProtocolCodec::decode_request(&task_2b3c_start_frame())
        .expect("exact fixed-width Start must decode");

    assert_eq!(request.kind(), ServiceQualificationRequestKind::Start);
}

#[test]
fn task_2b3c_rejects_unknown_version_without_reclassifying_it() {
    let mut frame = task_2b3c_start_frame();
    frame[8..10].copy_from_slice(&2_u16.to_be_bytes());

    assert!(ServiceQualificationProtocolCodec::decode_request(&frame).is_err());
}

#[test]
fn task_2b3c_exports_the_complete_typed_codec_boundary() {
    let _ = ServiceQualificationRejectionCode::Busy;
    let _ = accepts_public_reply_type;
    let _ = std::mem::size_of::<ServiceQualificationCommon>();
    let _ = std::mem::size_of::<ServiceQualificationRequestPayload>();
}
