use crate::v5_round5_test_store::{
    AllowlistContext, EvidenceContext, ReceiptContext, StageContext, StatefulStore,
};

fn drifted_states(receipt_generation: u64) -> Vec<crate::AuthorityStateSnapshot> {
    let base = crate::v5_envelope_test_support::state(receipt_generation);
    let mut states = Vec::new();
    macro_rules! drift {
        ($change:expr) => {{
            let mut changed = base.clone();
            $change(&mut changed);
            states.push(changed);
        }};
    }
    drift!(|s: &mut crate::AuthorityStateSnapshot| s.active_trust_generation += 1);
    drift!(|s: &mut crate::AuthorityStateSnapshot| s.active_receipt_generation = 6);
    drift!(|s: &mut crate::AuthorityStateSnapshot| s.active_allowlist_generation += 1);
    drift!(|s: &mut crate::AuthorityStateSnapshot| s.root.principal_id.push('x'));
    drift!(|s: &mut crate::AuthorityStateSnapshot| s.root.controlling_account_id.push('x'));
    drift!(|s: &mut crate::AuthorityStateSnapshot| s.root.lane_id.push('x'));
    drift!(|s: &mut crate::AuthorityStateSnapshot| s.root.key_id.push('x'));
    drift!(|s: &mut crate::AuthorityStateSnapshot| s.root.signature_profile_id.push('x'));
    drift!(|s: &mut crate::AuthorityStateSnapshot| s.root.public_key[0] ^= 1);
    drift!(|s: &mut crate::AuthorityStateSnapshot| s.root.key_epoch += 1);
    drift!(|s: &mut crate::AuthorityStateSnapshot| s.root_revocation_floor += 1);
    for index in 0..base.role_scope_floors.len() {
        let mut changed = base.clone();
        changed.role_scope_floors[index].revocation_epoch += 1;
        states.push(changed);
    }
    states
}

#[test]
fn receipt_rejects_every_authenticated_precondition_before_cas() {
    for state in drifted_states(4) {
        let context = ReceiptContext(StatefulStore::new(state));
        assert_eq!(
            crate::admit_prevalidated_promotion_authority_receipt_v5(
                crate::v5_round5_fixtures::receipt(),
                &context
            ),
            Err(crate::AuthorityError::PromotionBootstrapAdmissionConflict)
        );
        assert_eq!(context.0.calls.get(), 0);
    }
}

#[test]
fn stage_rejects_every_authenticated_precondition_before_cas() {
    for state in drifted_states(5) {
        let context = StageContext(StatefulStore::new(state));
        assert_eq!(
            crate::admit_prevalidated_stage_envelope_v2(
                crate::v5_round5_fixtures::stage(),
                &context
            ),
            Err(crate::AuthorityError::PromotionBootstrapAdmissionConflict)
        );
        assert_eq!(context.0.calls.get(), 0);
    }
}

#[test]
fn evidence_rejects_every_authenticated_precondition_before_cas() {
    for state in drifted_states(5) {
        let context = EvidenceContext(StatefulStore::new(state));
        assert_eq!(
            crate::admit_prevalidated_evidence_envelope_v2(
                crate::v5_round5_fixtures::evidence(),
                &context
            ),
            Err(crate::AuthorityError::PromotionBootstrapAdmissionConflict)
        );
        assert_eq!(context.0.calls.get(), 0);
    }
}

#[test]
fn allowlist_rejects_every_authenticated_precondition_before_cas() {
    for state in drifted_states(5) {
        let context = AllowlistContext(StatefulStore::new(state));
        assert_eq!(
            crate::admit_prevalidated_destination_allowlist_v1(
                crate::v5_round5_fixtures::allowlist(),
                &context
            ),
            Err(crate::AuthorityError::PromotionBootstrapAdmissionConflict)
        );
        assert_eq!(context.0.calls.get(), 0);
    }
}
