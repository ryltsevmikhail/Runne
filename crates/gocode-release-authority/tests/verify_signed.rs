#![cfg(feature = "fixture-only")]

use gocode_release_authority::{
    AuthenticatedThresholdTransition, AuthorityError, CommandId, Digest, Mutation, PromotionStore,
    ThresholdAdmission, ThresholdAdmissionRequest, ThresholdVerificationContext,
    ThresholdVerificationState, admit_prevalidated_signed_bundle,
};
use std::cell::{Cell, RefCell};
use std::collections::BTreeSet;

#[path = "canonical_wire/admission_support.rs"]
mod admission_support;
#[path = "canonical_wire/metadata_support.rs"]
mod metadata_support;
#[path = "verify_signed/support.rs"]
mod signing_support;
#[path = "canonical_wire/support.rs"]
mod support;
#[path = "threshold_support.rs"]
mod threshold_support;
#[path = "verify_signed/trust.rs"]
mod trust;
mod verified_stage_support;

use signing_support::signing_authorized;

struct Context {
    admitted: Cell<Option<(Digest, Digest)>>,
    acknowledged: RefCell<BTreeSet<Digest>>,
    calls: Cell<u8>,
    ack_calls: Cell<u8>,
    alias_keys: bool,
    max_role: Option<&'static str>,
}
impl Context {
    const fn valid() -> Self {
        Self {
            admitted: Cell::new(None),
            acknowledged: RefCell::new(BTreeSet::new()),
            calls: Cell::new(0),
            ack_calls: Cell::new(0),
            alias_keys: false,
            max_role: None,
        }
    }
}
impl ThresholdVerificationContext for Context {
    fn recover_existing(
        &self,
        request: &ThresholdAdmissionRequest<'_>,
    ) -> Result<Option<ThresholdAdmission>, AuthorityError> {
        let scope = request.scope().digest();
        match self.admitted.get() {
            None => Ok(None),
            Some((known, id)) if known == scope => {
                Ok(Some(ThresholdAdmission::ExistingSame { admission_id: id }))
            }
            Some(_) => Err(AuthorityError::BindingMismatch),
        }
    }
    fn trusted_state_and_now(&self) -> Result<(ThresholdVerificationState, u64), AuthorityError> {
        let mut state = ThresholdVerificationState {
            versions: ["root", "targets", "snapshot", "timestamp"]
                .into_iter()
                .map(|role| (role.into(), 1))
                .collect(),
            rollback_floor: 1,
            revocation_floor: 1,
            frozen: false,
            generation: 1,
            root_keys: threshold_support::threshold_keyset("r"),
            targets_keys: threshold_support::threshold_keyset("t"),
            snapshot_key: (
                "snapshot".into(),
                threshold_support::threshold_public_key("snapshot"),
            ),
            timestamp_key: (
                "timestamp".into(),
                threshold_support::threshold_public_key("timestamp"),
            ),
            channel_policy_id: Some("fixture-channel-policy".into()),
            role_bodies: std::collections::BTreeMap::new(),
            role_digests: std::collections::BTreeMap::new(),
        };
        if self.alias_keys {
            state.timestamp_key.1 = threshold_support::threshold_public_key("r1");
        }
        if let Some(role) = self.max_role {
            state.versions.insert(role.into(), u64::MAX);
        }
        Ok((state, 1))
    }
    fn persist_new(
        &self,
        transition: AuthenticatedThresholdTransition,
    ) -> Result<ThresholdAdmission, AuthorityError> {
        self.calls.set(self.calls.get() + 1);
        let admission_id = Digest::fixture([0x55; 32]);
        let scope = transition.scope().digest();
        match self.admitted.get() {
            None => {
                self.admitted.set(Some((scope, admission_id)));
                Ok(ThresholdAdmission::NewlyAdmitted { admission_id })
            }
            Some((known, id)) if known == scope => {
                Ok(ThresholdAdmission::ExistingSame { admission_id: id })
            }
            Some(_) => Err(AuthorityError::BindingMismatch),
        }
    }
    fn acknowledge_or_recover(
        &self,
        request: &gocode_release_authority::ThresholdAckRequest<'_>,
    ) -> Result<gocode_release_authority::ThresholdAckProof, AuthorityError> {
        if self.acknowledged.borrow_mut().insert(request.admission()) {
            self.ack_calls.set(self.ack_calls.get() + 1);
        }
        Ok(request.acknowledge())
    }
}

#[test]
fn registered_key_byte_alias_rejects_even_under_distinct_ids() {
    let (mut store, id, payloads) = signing_authorized();
    let signed_bundle = signing_support::leased_bundle(&mut store, &id, &payloads);
    let receipt = store
        .reserve_verify_signed(&id, 4, CommandId::fixture("verify"), &signed_bundle)
        .unwrap();
    let context = Context {
        alias_keys: true,
        ..Context::valid()
    };
    assert_eq!(
        admit_prevalidated_signed_bundle(signed_bundle, receipt, &context),
        Err(AuthorityError::BindingMismatch)
    );
}

#[test]
fn every_threshold_role_rejects_maximum_version_successor() {
    for role in ["root", "targets", "snapshot", "timestamp"] {
        let (mut store, id, payloads) = signing_authorized();
        let signed_bundle = signing_support::leased_bundle(&mut store, &id, &payloads);
        let receipt = store
            .reserve_verify_signed(&id, 4, CommandId::fixture("verify"), &signed_bundle)
            .unwrap();
        let context = Context {
            max_role: Some(role),
            ..Context::valid()
        };
        assert_eq!(
            admit_prevalidated_signed_bundle(signed_bundle, receipt, &context),
            Err(AuthorityError::BindingMismatch)
        );
    }
}

#[test]
fn foreign_store_cannot_recover_a_reserved_scope() {
    let (mut store, id, payloads) = signing_authorized();
    let context = Context::valid();
    let first = signing_support::leased_bundle(&mut store, &id, &payloads);
    let receipt = store
        .reserve_verify_signed(&id, 4, CommandId::fixture("verify"), &first)
        .unwrap();
    drop(admit_prevalidated_signed_bundle(first, receipt, &context).unwrap());
    let (mut resumed_store, resumed_id, _) = signing_authorized();
    let resumed = signing_support::leased_bundle(&mut resumed_store, &resumed_id, &payloads);
    assert_eq!(
        store.reserve_verify_signed(&id, 4, CommandId::fixture("verify"), &resumed),
        Err(AuthorityError::BindingMismatch)
    );
    assert_eq!(context.calls.get(), 1);
}

#[test]
fn reservation_threshold_proof_transition_and_idempotent_ack() {
    let (mut store, id, payloads) = signing_authorized();
    let signed_bundle = signing_support::leased_bundle(&mut store, &id, &payloads);
    let receipt = store
        .reserve_verify_signed(&id, 4, CommandId::fixture("verify"), &signed_bundle)
        .unwrap();
    let duplicate = store
        .reserve_verify_signed(&id, 4, CommandId::fixture("verify"), &signed_bundle)
        .unwrap();
    assert_eq!(receipt, duplicate);
    let context = Context::valid();
    let proof = admit_prevalidated_signed_bundle(signed_bundle, receipt, &context).unwrap();
    let outcome = store
        .transact(
            &id,
            4,
            CommandId::fixture("verify"),
            Mutation::VerifySigned {
                proof: Box::new(proof),
            },
        )
        .unwrap();
    assert_eq!(outcome.revision, 5);
    assert_eq!(context.calls.get(), 1);
    assert_eq!(
        store.transact(
            &id,
            5,
            CommandId::fixture("r3"),
            Mutation::StartRc3Review {}
        ),
        Err(AuthorityError::BindingMismatch)
    );
    assert_eq!(
        store.acknowledge_threshold_completion(&id, 4, CommandId::fixture("ack"), &context),
        Err(AuthorityError::StaleRevision)
    );
    assert_eq!(context.ack_calls.get(), 0);
    assert_eq!(
        store
            .acknowledge_threshold_completion(&id, 5, CommandId::fixture("ack"), &context)
            .unwrap()
            .revision,
        6
    );
    assert_eq!(
        store
            .acknowledge_threshold_completion(&id, 5, CommandId::fixture("ack"), &context)
            .unwrap()
            .revision,
        6
    );
    assert_eq!(context.acknowledged.borrow().len(), 1);
    assert_eq!(context.ack_calls.get(), 1);
    assert_eq!(
        store.acknowledge_threshold_completion(
            &id,
            5,
            CommandId::fixture("different-ack"),
            &context,
        ),
        Err(AuthorityError::CommandReplayDiverged)
    );
    assert_eq!(context.ack_calls.get(), 1);
}

#[test]
fn divergent_or_competing_reservation_fails_closed() {
    let (mut store, id, payloads) = signing_authorized();
    let bundle = signing_support::leased_bundle(&mut store, &id, &payloads);
    store
        .reserve_verify_signed(&id, 4, CommandId::fixture("verify"), &bundle)
        .unwrap();
    assert_eq!(
        store.reserve_verify_signed(&id, 4, CommandId::fixture("other"), &bundle),
        Err(AuthorityError::CommandReplayDiverged)
    );
    assert_eq!(
        store.transact(
            &id,
            4,
            CommandId::fixture("r3"),
            Mutation::StartRc3Review {}
        ),
        Err(AuthorityError::BindingMismatch)
    );
}
