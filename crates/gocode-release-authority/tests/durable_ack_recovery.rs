#![cfg(feature = "fixture-only")]

use gocode_release_authority::{
    AuthorityError, CommandId, Digest, DurableFixturePromotionAuthority,
    DurableFixtureThresholdContext, Mutation, PromotionStore, ThresholdFixtureStoreBinding,
    ThresholdVerificationContext, ThresholdVerificationState, admit_prevalidated_signed_bundle,
};

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
mod verified_stage_support;

struct CrashAfterRemote<'a>(&'a DurableFixtureThresholdContext);
impl ThresholdVerificationContext for CrashAfterRemote<'_> {
    fn recover_existing(
        &self,
        request: &gocode_release_authority::ThresholdAdmissionRequest<'_>,
    ) -> Result<Option<gocode_release_authority::ThresholdAdmission>, AuthorityError> {
        self.0.recover_existing(request)
    }
    fn trusted_state_and_now(&self) -> Result<(ThresholdVerificationState, u64), AuthorityError> {
        self.0.trusted_state_and_now()
    }
    fn persist_new(
        &self,
        transition: gocode_release_authority::AuthenticatedThresholdTransition,
    ) -> Result<gocode_release_authority::ThresholdAdmission, AuthorityError> {
        self.0.persist_new(transition)
    }
    fn acknowledge_or_recover(
        &self,
        request: &gocode_release_authority::ThresholdAckRequest<'_>,
    ) -> Result<gocode_release_authority::ThresholdAckProof, AuthorityError> {
        self.0.acknowledge_or_recover(request)?;
        Err(AuthorityError::DurableStateUnavailable)
    }
}

#[test]
fn acknowledged_remote_tombstone_recovers_once_after_both_files_reopen() {
    let root = std::env::temp_dir().join(format!("gocode-ack-recovery-{}", std::process::id()));
    let promotion = root.with_extension("promotion");
    let threshold = root.with_extension("threshold");
    for path in [
        &promotion,
        &promotion.with_extension("promotion.lease"),
        &threshold,
        &threshold.with_extension("threshold.lease"),
    ] {
        let _ = std::fs::remove_file(path);
    }
    let (mut memory, id, payloads) = signing_support::signing_authorized();
    let binding = ThresholdFixtureStoreBinding::new(
        Digest::fixture(verified_stage_support::bootstrap_digest()),
        "fixture-v1",
        1,
    )
    .unwrap();
    let bundle = signing_support::leased_bundle(&mut memory, &id, &payloads);
    let context =
        DurableFixtureThresholdContext::create(&threshold, binding.clone(), fixture_state(), 1)
            .unwrap();
    let mut store = DurableFixturePromotionAuthority::create_from_in_memory(
        &promotion,
        binding.clone(),
        &memory,
    )
    .unwrap();
    let receipt = store
        .reserve_verify_signed(&id, 4, CommandId::fixture("verify"), &bundle)
        .unwrap();
    let proof = admit_prevalidated_signed_bundle(bundle, receipt, &context).unwrap();
    store
        .transact(
            &id,
            4,
            CommandId::fixture("verify"),
            Mutation::VerifySigned {
                proof: Box::new(proof),
            },
        )
        .unwrap();
    assert_eq!(
        store.acknowledge_threshold_completion(
            &id,
            5,
            CommandId::fixture("ack"),
            &CrashAfterRemote(&context)
        ),
        Err(AuthorityError::DurableStateUnavailable)
    );
    assert!(
        std::str::from_utf8(&std::fs::read(&threshold).unwrap())
            .unwrap()
            .contains("ack_count=1")
    );
    drop(store);
    drop(context);
    let context = DurableFixtureThresholdContext::reopen(&threshold, binding.clone()).unwrap();
    let mut store = DurableFixturePromotionAuthority::reopen(&promotion, binding).unwrap();
    assert_eq!(
        store.acknowledge_threshold_completion(&id, 5, CommandId::fixture("other"), &context),
        Err(AuthorityError::CommandReplayDiverged)
    );
    assert_eq!(
        store.acknowledge_threshold_completion(&id, 6, CommandId::fixture("ack"), &context),
        Err(AuthorityError::StaleRevision)
    );
    let settled = store
        .acknowledge_threshold_completion(&id, 5, CommandId::fixture("ack"), &context)
        .unwrap();
    assert_eq!(settled.revision, 6);
    let snapshot = store.snapshot(&id).unwrap();
    assert_eq!(
        store
            .acknowledge_threshold_completion(&id, 5, CommandId::fixture("ack"), &context)
            .unwrap(),
        settled
    );
    assert_eq!(store.snapshot(&id).unwrap(), snapshot);
    assert!(
        std::str::from_utf8(&std::fs::read(&threshold).unwrap())
            .unwrap()
            .contains("journal_count=1")
    );
    drop(store);
    drop(context);
    for path in [
        &promotion,
        &promotion.with_extension("promotion.lease"),
        &threshold,
        &threshold.with_extension("threshold.lease"),
    ] {
        std::fs::remove_file(path).unwrap();
    }
}

fn fixture_state() -> ThresholdVerificationState {
    ThresholdVerificationState {
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
    }
}
