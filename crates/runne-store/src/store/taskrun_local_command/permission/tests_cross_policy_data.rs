//! Conditional scope/selection DATA only. No FullAccess trusted receipt or native auth.
use super::super::{
    admission_checks, model::now_ms, original_approval_facts::OriginalApprovalFacts,
    retained_policy, retained_policy_rows,
};
use super::support::Case;
use runne_application::permission_modes::PermissionMode;
use runne_application::{permission_modes::*, project_trust::*};

#[test]
fn data_all_six_human_pairs_keep_componentwise_allow_ask_and_deny_precedence() {
    let c = Case::new(true);
    let mut writer = c.f.store.inner.writer.lock().unwrap();
    let tx = writer.transaction().unwrap();
    let (capture, context) = retained_policy_rows::load(&tx, c.b.assignment().taskrun_id).unwrap();
    let context = context.unwrap();
    let now = now_ms();
    let verified = admission_checks::classify_original_admission(
        &tx,
        &capture,
        &OriginalApprovalFacts::from_context(&context),
        now,
    )
    .unwrap();
    let modes = [
        PermissionMode::AskAlways,
        PermissionMode::RiskBased,
        PermissionMode::FullAccess,
    ];
    let mut pairs = 0;
    for old_mode in modes {
        for new_mode in modes {
            if old_mode == new_mode {
                continue;
            }
            let mut old_selection = context.selection.clone();
            old_selection.selected_mode = old_mode;
            let mut current_selection = old_selection.clone();
            current_selection.selected_mode = new_mode;
            assert_eq!(
                retained_policy::selection_stop_for_admission(
                    &old_selection,
                    &current_selection,
                    context.approval.expires_at_unix_ms,
                    now,
                    Some(&verified)
                ),
                None
            );
            for class in ManagedEffectClass::ALL
                .into_iter()
                .filter(|v| *v != ManagedEffectClass::NetworkUse)
            {
                for original in [ManagedEffectDecision::Allow, ManagedEffectDecision::Ask] {
                    for current in [
                        ManagedEffectDecision::Allow,
                        ManagedEffectDecision::Ask,
                        ManagedEffectDecision::Deny,
                    ] {
                        let mut before = context.closed_snapshot;
                        before.policy = before.policy.with_decision(class, original);
                        let mut after = before;
                        after.record.revision += 1;
                        after.policy = after.policy.with_decision(class, current);
                        let mut original_scope = context.scope.clone();
                        original_scope.managed_policy =
                            ManagedPolicyCoverage::from_closed_snapshot(c.f.trust_id(), &before)
                                .unwrap();
                        let mut current_scope = original_scope.clone();
                        current_scope.managed_policy =
                            ManagedPolicyCoverage::from_closed_snapshot(c.f.trust_id(), &after)
                                .unwrap();
                        let compatible = assess_retained_scope_compatibility_v1(
                            c.f.trust_id(),
                            &original_scope,
                            &before,
                            c.f.trust_id(),
                            &current_scope,
                            &after,
                            1,
                            FROZEN_POLICY_VERSION,
                            LOCAL_COMMAND_POLICY_VERSION,
                        );
                        if current == ManagedEffectDecision::Deny {
                            assert_eq!(
                                current_scope
                                    .managed_policy
                                    .scope_minimum_disposition(&current_scope),
                                Some(ManagedEffectDecision::Deny)
                            );
                            assert_eq!(compatible, RetainedScopeCompatibilityV1::RelevantChange);
                        } else if current == original {
                            assert!(matches!(
                                compatible,
                                RetainedScopeCompatibilityV1::Compatible { .. }
                            ));
                        } else {
                            assert_eq!(compatible, RetainedScopeCompatibilityV1::RelevantChange);
                        }
                    }
                }
            }
            pairs += 1;
        }
    }
    assert_eq!(pairs, 6);
}

#[test]
fn historical_verified_original_is_not_live_at_expiry_data_boundary() {
    let c = Case::new(true);
    c.f.store
        .record_local_command_permission_stop(c.b.assignment(), &c.b, 5)
        .unwrap();
    let mut writer = c.f.store.inner.writer.lock().unwrap();
    let tx = writer.transaction().unwrap();
    let (capture, context) = retained_policy_rows::load(&tx, c.b.assignment().taskrun_id).unwrap();
    let context = context.unwrap();
    let facts = OriginalApprovalFacts::from_context(&context);
    let now = now_ms();
    let historic = admission_checks::verify_original_admission(
        &tx,
        &facts,
        &capture.binding_digest,
        now,
        true,
    )
    .unwrap();
    assert!(historic.live_human(now));
    // Only the pure DATA lifetime boundary advances here; no fake runtime/admission clock.
    assert!(!historic.live_human(context.approval.expires_at_unix_ms));
    assert_eq!(
        retained_policy::selection_stop_for_admission(
            &context.selection,
            &context.selection,
            context.approval.expires_at_unix_ms,
            context.approval.expires_at_unix_ms,
            Some(&historic)
        ),
        Some(5)
    );
    assert_eq!(
        super::super::stop::stop_reason(
            &tx,
            c.b.assignment().taskrun_id.as_bytes(),
            c.b.assignment().attempt_id.as_bytes(),
            &capture.binding_digest
        )
        .unwrap(),
        Some(5)
    );
}
