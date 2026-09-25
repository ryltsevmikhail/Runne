use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use zeroize::Zeroizing;

use crate::frame::{FrameDropWitness, NativeReplyFrame, NativeRequestFrame};

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

#[test]
fn observed_frame_records_drop_once() {
    let drops = Arc::new(AtomicUsize::new(0));
    let frame = NativeRequestFrame::new_observed(
        Zeroizing::new(vec![1]),
        FrameDropWitness::new(Arc::clone(&drops)),
    )
    .unwrap();

    assert_eq!(drops.load(Ordering::Acquire), 0);
    drop(frame);
    assert_eq!(drops.load(Ordering::Acquire), 1);
}
