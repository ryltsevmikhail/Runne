//! Closed managed effect policy compiler and canonical V2 binding digest.

use runne_application::project_trust::ManagedEffectDecision;
pub use runne_application::project_trust::managed_effect_policy_digest_v2;
pub use runne_application::project_trust::{
    ManagedEffectClass, ManagedEffectPolicyV1, ProjectTrustEffectPolicySnapshot,
};

/// The compiled result of combining a managed class with prior T1 and preset gates.
pub type EffectDecision = ManagedEffectDecision;

/// Compiles a closed effect class over an already-admitted T1/preset decision.
///
/// Callers must first apply the existing source or local-command gate, including
/// its frozen path checks. This class-wide overlay has no destination or path ACL
/// semantics. Invalid snapshots and unknown versions always compile to deny.
pub fn compile_effect_policy(
    snapshot: &ProjectTrustEffectPolicySnapshot,
    class: ManagedEffectClass,
    prior: EffectDecision,
) -> EffectDecision {
    if !snapshot.is_valid() {
        return EffectDecision::Deny;
    }
    let managed = snapshot.policy.decision_for(class);
    if managed == EffectDecision::Deny || prior == EffectDecision::Deny {
        EffectDecision::Deny
    } else if managed == EffectDecision::Ask || prior == EffectDecision::Ask {
        EffectDecision::Ask
    } else {
        EffectDecision::Allow
    }
}
