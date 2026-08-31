use std::time::Duration;

use runne_api::{ApiPrincipalId, DaemonInstanceId, RuntimeSessionBinding, StableRuntimeBinding};
use runne_application::local_session::AuthenticatedRuntimeSession;
use runne_domain::{event::Sensitivity, id::EventLogLineageId};

pub(super) fn authenticated_session() -> AuthenticatedRuntimeSession {
    let stable = StableRuntimeBinding::new(
        [1, 143, 46, 58, 112, 0, 112, 0, 128, 0, 0, 0, 0, 0, 0, 1],
        ApiPrincipalId::new("local-owner").unwrap(),
        "018f2e3a-7000-7000-8000-000000000003"
            .parse::<EventLogLineageId>()
            .unwrap(),
        "gocode-ui-client/2",
        [3; 32],
        [4; 32],
    )
    .unwrap();
    let binding = RuntimeSessionBinding::new(
        stable,
        DaemonInstanceId::from_bytes([1, 143, 46, 58, 112, 0, 112, 0, 128, 0, 0, 0, 0, 0, 0, 2]),
        7,
        [5; 16],
        3,
        Sensitivity::Internal,
        [6; 32],
    )
    .unwrap();
    AuthenticatedRuntimeSession {
        binding,
        expires_at_monotonic: Duration::from_secs(600),
    }
}
