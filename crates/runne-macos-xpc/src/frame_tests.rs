use zeroize::Zeroizing;

use crate::frame::{NativeReplyFrame, NativeRequestFrame};

#[test]
fn native_frames_reject_empty_and_oversized_request_or_reply() {
    assert!(NativeRequestFrame::new(Zeroizing::new(Vec::new())).is_err());
    assert!(NativeReplyFrame::new(Zeroizing::new(Vec::new())).is_err());
    let oversized =
        vec![0; runne_platform_ports::credential_service::MAX_CREDENTIAL_SERVICE_FRAME_BYTES + 1];
    assert!(NativeRequestFrame::new(Zeroizing::new(oversized.clone())).is_err());
    assert!(NativeReplyFrame::new(Zeroizing::new(oversized)).is_err());
    assert_eq!(
        &*NativeRequestFrame::new(Zeroizing::new(vec![1]))
            .unwrap()
            .into_bytes(),
        &[1]
    );
    assert_eq!(
        &*NativeReplyFrame::new(Zeroizing::new(vec![2]))
            .unwrap()
            .into_bytes(),
        &[2]
    );
}
