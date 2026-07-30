use std::time::Duration;

use gocode_runtime_client::{MAXIMUM_SSE_FRAME_BYTES, SSE_SILENCE_TIMEOUT};

#[test]
fn public_sse_limits_match_the_versioned_contract() {
    assert_eq!(MAXIMUM_SSE_FRAME_BYTES, 256 * 1024);
    assert_eq!(SSE_SILENCE_TIMEOUT, Duration::from_secs(45));
}
