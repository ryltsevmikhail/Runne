// P2-1 pin for the semantic fix (report 2026-09-19-t1 §2): the
// recovery re-adopt path maps a trust denial (trust gate `Rejected`) to
// `ProcessHostError::Forbidden`, NOT `Conflict`. Conflict is reserved for
// durable state clashes (an invocation already adopted elsewhere); a policy
// denial is Forbidden like every other trust-driven rejection on the
// daemon surface (`trust_gate.rs` maps Denied → Forbidden). The mapping
// must hold so a future unfreeze of the activation-gated process channel
// cannot silently reclassify trust denials as state conflicts.

use runne_api::ProcessHostError;
use runne_platform_desktop::RootHandleBrokerError;

// The helper lives in the recovery include-module (via `super::*`); it is
// re-exercised here directly so the mapping is pinned independently of a
// durable fixture.
#[test]
fn p2_1_trust_denial_on_readopt_maps_to_forbidden_not_conflict() {
    // Rejected from the trust gate = policy denial → Forbidden.
    assert_eq!(
        super::map_re_adopt_host_error_for_tests(RootHandleBrokerError::Rejected),
        ProcessHostError::Forbidden,
        "trust denial must surface as Forbidden, not Conflict"
    );
    // Unavailable stays Unavailable (fail-closed authority loss).
    assert_eq!(
        super::map_re_adopt_host_error_for_tests(RootHandleBrokerError::Unavailable),
        ProcessHostError::Unavailable,
        "authority loss stays Unavailable"
    );
}
