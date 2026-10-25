//! DATA-only decision matrix from a real capture's scope; not live policy administration.
use super::support::Case;
use runne_application::{permission_modes::*, project_trust::*};

fn compare(
    c: &Case,
    class: ManagedEffectClass,
    old: ManagedEffectDecision,
    new: ManagedEffectDecision,
) -> RetainedScopeCompatibilityV1 {
    let mut before = c.b.closed_rules_snapshot();
    before.policy = before.policy.with_decision(class, old);
    let mut after = before;
    after.record.revision += 1;
    after.policy = after.policy.with_decision(class, new);
    // Distinct decision values, not a trust/mask identity change or metadata-only revision.
    assert_eq!(before.record.status, after.record.status);
    assert_eq!(
        before.record.managed_deny_mask,
        after.record.managed_deny_mask
    );
    let mut original = c.b.scope().clone();
    original.managed_policy =
        ManagedPolicyCoverage::from_closed_snapshot(c.f.trust_id(), &before).unwrap();
    let mut current = original.clone();
    current.managed_policy =
        ManagedPolicyCoverage::from_closed_snapshot(c.f.trust_id(), &after).unwrap();
    original.validate().unwrap();
    current.validate().unwrap();
    if class != ManagedEffectClass::NetworkUse && new == ManagedEffectDecision::Deny {
        assert_eq!(
            current.managed_policy.scope_minimum_disposition(&current),
            Some(ManagedEffectDecision::Deny)
        );
    }
    assess_retained_scope_compatibility_v1(
        c.f.trust_id(),
        &original,
        &before,
        c.f.trust_id(),
        &current,
        &after,
        1,
        FROZEN_POLICY_VERSION,
        LOCAL_COMMAND_POLICY_VERSION,
    )
}

#[test]
fn data_nonprovided_network_decision_drift_is_compatible_not_authority() {
    let c = Case::new(false);
    let original_digest = c.b.digest();
    for old in [
        ManagedEffectDecision::Allow,
        ManagedEffectDecision::Ask,
        ManagedEffectDecision::Deny,
    ] {
        for new in [
            ManagedEffectDecision::Allow,
            ManagedEffectDecision::Ask,
            ManagedEffectDecision::Deny,
        ] {
            assert!(matches!(
                compare(&c, ManagedEffectClass::NetworkUse, old, new),
                RetainedScopeCompatibilityV1::Compatible { .. }
            ));
        }
    }
    assert_eq!(c.b.digest(), original_digest);
    assert_eq!(c.spent_on_owned_reopen(), 0);
}

#[test]
fn data_provided_ask_allow_changes_are_not_normalized_and_deny_remains_deny() {
    let c = Case::new(false);
    for class in ManagedEffectClass::ALL
        .into_iter()
        .filter(|x| *x != ManagedEffectClass::NetworkUse)
    {
        for (old, new) in [
            (ManagedEffectDecision::Allow, ManagedEffectDecision::Ask),
            (ManagedEffectDecision::Ask, ManagedEffectDecision::Allow),
            (ManagedEffectDecision::Allow, ManagedEffectDecision::Deny),
            (ManagedEffectDecision::Ask, ManagedEffectDecision::Deny),
        ] {
            assert_eq!(
                compare(&c, class, old, new),
                RetainedScopeCompatibilityV1::RelevantChange
            );
        }
        assert!(matches!(
            compare(
                &c,
                class,
                ManagedEffectDecision::Ask,
                ManagedEffectDecision::Ask
            ),
            RetainedScopeCompatibilityV1::Compatible { .. }
        ));
    }
    assert_eq!(c.spent_on_owned_reopen(), 0);
}

#[test]
fn data_valid_nonmanaged_identity_shapes_cannot_borrow_original_scope() {
    let c = Case::new(false);
    let snapshot = c.b.closed_rules_snapshot();
    let original = c.b.scope();
    let mut variants = Vec::new();
    let mut current = original.clone();
    current.lifetime_ms -= 1;
    variants.push(current);
    let mut current = original.clone();
    current.permission_scope.principal_id =
        runne_api::ApiPrincipalId::new("other-principal").unwrap();
    variants.push(current);
    let mut current = original.clone();
    current
        .permission_scope
        .runtime_authority_id
        .0
        .push_str("-other");
    variants.push(current);
    let mut current = original.clone();
    current.permission_scope.workspace_id =
        runne_domain::id::WorkspaceId::from_bytes(uuid::Uuid::now_v7().into_bytes());
    variants.push(current);
    assert!(matches!(
        assess_retained_scope_compatibility_v1(
            c.f.trust_id(),
            original,
            &snapshot,
            c.f.trust_id(),
            original,
            &snapshot,
            1,
            FROZEN_POLICY_VERSION,
            LOCAL_COMMAND_POLICY_VERSION
        ),
        RetainedScopeCompatibilityV1::Compatible { .. }
    ));
    for current in variants {
        current.validate().unwrap();
        assert_eq!(
            assess_retained_scope_compatibility_v1(
                c.f.trust_id(),
                original,
                &snapshot,
                c.f.trust_id(),
                &current,
                &snapshot,
                1,
                FROZEN_POLICY_VERSION,
                LOCAL_COMMAND_POLICY_VERSION
            ),
            RetainedScopeCompatibilityV1::IdentityChanged
        );
    }
}
