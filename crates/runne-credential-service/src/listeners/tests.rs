use std::time::Duration;

use runne_macos_xpc::{
    CredentialServiceEndpointRole, CredentialServiceRequestHandler, CredentialServiceXpcError,
};
use zeroize::Zeroizing;

use super::{IdlePolicy, ServiceHandler};

#[test]
fn idle_shutdown_requires_every_owner_to_be_quiescent() {
    let policy = IdlePolicy::new(30_000);
    assert!(!policy.should_stop(Duration::from_millis(29_999), 0, 0, false));
    assert!(!policy.should_stop(Duration::from_secs(30), 1, 0, false));
    assert!(!policy.should_stop(Duration::from_secs(30), 0, 1, false));
    assert!(!policy.should_stop(Duration::from_secs(30), 0, 0, true));
    assert!(policy.should_stop(Duration::from_secs(30), 0, 0, false));
}

#[test]
fn malformed_pre_context_frame_requires_connection_invalidation() {
    let handler = ServiceHandler::new().expect("handler");
    assert_eq!(
        handler.handle(
            CredentialServiceEndpointRole::Runtime,
            Zeroizing::new(vec![0xff]),
        ),
        Err(CredentialServiceXpcError::Invalidated)
    );
}
