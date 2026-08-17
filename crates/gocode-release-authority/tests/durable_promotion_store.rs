#![cfg(feature = "fixture-only")]

use gocode_release_authority::{
    AuthenticatedThresholdTransition, CommandId, Digest, DurableFixturePromotionAuthority,
    Mutation, PromotionStore, ThresholdAdmission, ThresholdAdmissionRequest,
    ThresholdFixtureStoreBinding, ThresholdVerificationContext, ThresholdVerificationState,
    admit_prevalidated_signed_bundle,
};
use sha2::{Digest as _, Sha256};
use std::cell::Cell;

#[path = "canonical_wire/admission_support.rs"]
mod admission_support;
#[path = "canonical_wire/metadata_support.rs"]
mod metadata_support;
#[path = "verify_signed/support.rs"]
mod signing_support;
#[path = "canonical_wire/support.rs"]
mod support;
mod verified_stage_support;

#[test]
#[rustfmt::skip]
fn durable_store_reopens_an_exact_verify_reservation() {
    let path = std::env::temp_dir()
        .join(format!("gocode-promotion-store-{}", std::process::id()));
    let _ = std::fs::remove_file(&path);
    let (mut memory, id, payloads) = signing_support::signing_authorized();
    let bundle = signing_support::leased_bundle(&mut memory, &id, &payloads);
    let binding = ThresholdFixtureStoreBinding::new(Digest::fixture(verified_stage_support::bootstrap_digest()), "fixture-v1", 1).unwrap();
    let mut store = DurableFixturePromotionAuthority::create_from_in_memory(&path, binding.clone(), &memory).unwrap();
    let expected = store
        .reserve_verify_signed(&id, 4, CommandId::fixture("verify"), &bundle)
        .unwrap();
    drop(store);
    let mut reopened = DurableFixturePromotionAuthority::reopen(&path, binding).unwrap();
    assert_eq!(
        reopened
            .reserve_verify_signed(&id, 4, CommandId::fixture("verify"), &bundle)
            .unwrap(),
        expected,
    );
    std::fs::remove_file(path).unwrap();
}

#[test]
#[rustfmt::skip]
fn durable_store_rejects_a_second_live_path_owner() {
    let path = std::env::temp_dir().join(format!("gocode-promotion-lease-{}", std::process::id())); let _ = std::fs::remove_file(&path); let _ = std::fs::remove_file(path.with_extension("lease"));
    let (memory, _id, _) = signing_support::signing_authorized();
    let binding = ThresholdFixtureStoreBinding::new(Digest::fixture(verified_stage_support::bootstrap_digest()), "fixture-v1", 1).unwrap(); let owner = DurableFixturePromotionAuthority::create_from_in_memory(&path, binding.clone(), &memory).unwrap(); assert!(matches!(DurableFixturePromotionAuthority::reopen(&path, binding), Err(gocode_release_authority::AuthorityError::DurableStateUnavailable))); drop(owner); std::fs::remove_file(path).unwrap();
}

struct Remote(Cell<u8>);
impl ThresholdVerificationContext for Remote {
    fn recover_existing(
        &self,
        _: &ThresholdAdmissionRequest<'_>,
    ) -> Result<Option<ThresholdAdmission>, gocode_release_authority::AuthorityError> {
        self.0.set(self.0.get() + 1);
        Ok(Some(ThresholdAdmission::ExistingSame {
            admission_id: Digest::fixture([9; 32]),
        }))
    }
    fn trusted_state_and_now(
        &self,
    ) -> Result<(ThresholdVerificationState, u64), gocode_release_authority::AuthorityError> {
        unreachable!("persist is selected by test fixture")
    }
    fn persist_new(
        &self,
        _: AuthenticatedThresholdTransition,
    ) -> Result<ThresholdAdmission, gocode_release_authority::AuthorityError> {
        self.0.set(self.0.get() + 1);
        Ok(ThresholdAdmission::NewlyAdmitted {
            admission_id: Digest::fixture([9; 32]),
        })
    }
    fn acknowledge_or_recover(
        &self,
        request: &gocode_release_authority::ThresholdAckRequest<'_>,
    ) -> Result<gocode_release_authority::ThresholdAckProof, gocode_release_authority::AuthorityError>
    {
        self.0.set(self.0.get() + 1);
        Ok(request.acknowledge())
    }
}

struct FlakyRemote {
    calls: Cell<u8>,
    fail: Cell<bool>,
}
impl ThresholdVerificationContext for FlakyRemote {
    fn recover_existing(
        &self,
        _: &ThresholdAdmissionRequest<'_>,
    ) -> Result<Option<ThresholdAdmission>, gocode_release_authority::AuthorityError> {
        Ok(Some(ThresholdAdmission::ExistingSame {
            admission_id: Digest::fixture([9; 32]),
        }))
    }
    fn trusted_state_and_now(
        &self,
    ) -> Result<(ThresholdVerificationState, u64), gocode_release_authority::AuthorityError> {
        unreachable!()
    }
    fn persist_new(
        &self,
        _: AuthenticatedThresholdTransition,
    ) -> Result<ThresholdAdmission, gocode_release_authority::AuthorityError> {
        unreachable!()
    }
    fn acknowledge_or_recover(
        &self,
        request: &gocode_release_authority::ThresholdAckRequest<'_>,
    ) -> Result<gocode_release_authority::ThresholdAckProof, gocode_release_authority::AuthorityError>
    {
        self.calls.set(self.calls.get() + 1);
        if self.fail.replace(false) {
            return Err(gocode_release_authority::AuthorityError::DurableStateUnavailable);
        }
        Ok(request.acknowledge())
    }
}

#[test]
fn persisted_delivering_reopens_only_for_the_exact_ack_claim() {
    let path = std::env::temp_dir().join(format!(
        "gocode-promotion-delivering-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_file(path.with_extension("lease"));
    let (mut memory, id, payloads) = signing_support::signing_authorized();
    let bundle = signing_support::leased_bundle(&mut memory, &id, &payloads);
    let binding = ThresholdFixtureStoreBinding::new(
        Digest::fixture(verified_stage_support::bootstrap_digest()),
        "fixture-v1",
        1,
    )
    .unwrap();
    let mut store =
        DurableFixturePromotionAuthority::create_from_in_memory(&path, binding.clone(), &memory)
            .unwrap();
    let receipt = store
        .reserve_verify_signed(&id, 4, CommandId::fixture("verify"), &bundle)
        .unwrap();
    let proof = admit_prevalidated_signed_bundle(bundle, receipt, &Remote(Cell::new(0))).unwrap();
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
    let remote = FlakyRemote {
        calls: Cell::new(0),
        fail: Cell::new(true),
    };
    assert_eq!(
        store.acknowledge_threshold_completion(&id, 5, CommandId::fixture("ack"), &remote),
        Err(gocode_release_authority::AuthorityError::DurableStateUnavailable)
    );
    drop(store);
    let mut reopened = DurableFixturePromotionAuthority::reopen(&path, binding).unwrap();
    assert_eq!(
        reopened.transact(
            &id,
            5,
            CommandId::fixture("r3"),
            Mutation::StartRc3Review {}
        ),
        Err(gocode_release_authority::AuthorityError::BindingMismatch)
    );
    assert_eq!(
        reopened.acknowledge_threshold_completion(&id, 5, CommandId::fixture("other"), &remote),
        Err(gocode_release_authority::AuthorityError::CommandReplayDiverged)
    );
    assert_eq!(
        reopened
            .acknowledge_threshold_completion(&id, 5, CommandId::fixture("ack"), &remote)
            .unwrap()
            .revision,
        6
    );
    assert_eq!(remote.calls.get(), 2);
    drop(reopened);
    std::fs::remove_file(path).unwrap();
}

#[test]
fn durable_store_converges_after_each_threshold_crash_boundary() {
    let path = std::env::temp_dir().join(format!("gocode-promotion-crash-{}", std::process::id()));
    let _ = std::fs::remove_file(&path);
    let (mut memory, id, payloads) = signing_support::signing_authorized();
    let bundle = signing_support::leased_bundle(&mut memory, &id, &payloads);
    let binding = ThresholdFixtureStoreBinding::new(
        Digest::fixture(verified_stage_support::bootstrap_digest()),
        "fixture-v1",
        1,
    )
    .unwrap();
    let mut store =
        DurableFixturePromotionAuthority::create_from_in_memory(&path, binding.clone(), &memory)
            .unwrap();
    let remote = Remote(Cell::new(0));
    let receipt = store
        .reserve_verify_signed(&id, 4, CommandId::fixture("verify"), &bundle)
        .unwrap();
    drop(store); // crash after reservation
    let store = DurableFixturePromotionAuthority::reopen(&path, binding.clone()).unwrap();
    let proof = admit_prevalidated_signed_bundle(bundle, receipt, &remote).unwrap();
    assert_eq!(remote.0.get(), 1); // crash after remote admission before VerifySigned
    drop(store);
    let mut store = DurableFixturePromotionAuthority::reopen(&path, binding.clone()).unwrap();
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
    drop(store); // crash after VerifySigned Pending
    let mut store = DurableFixturePromotionAuthority::reopen(&path, binding.clone()).unwrap();
    assert_eq!(
        store
            .acknowledge_threshold_completion(&id, 5, CommandId::fixture("ack"), &remote)
            .unwrap()
            .revision,
        6
    );
    drop(store); // crash after local settled ACK
    let mut store = DurableFixturePromotionAuthority::reopen(&path, binding).unwrap();
    assert_eq!(
        store
            .acknowledge_threshold_completion(&id, 5, CommandId::fixture("ack"), &remote)
            .unwrap()
            .revision,
        6
    );
    assert_eq!(remote.0.get(), 2); // no additional remote calls after tombstone
    std::fs::remove_file(path).unwrap();
}

#[test]
fn durable_snapshot_digest_excludes_lf_and_chains_after_reopen() {
    let path =
        std::env::temp_dir().join(format!("gocode-promotion-snapshot-{}", std::process::id()));
    let _ = std::fs::remove_file(&path);
    let (mut memory, id, payloads) = signing_support::signing_authorized();
    let bundle = signing_support::leased_bundle(&mut memory, &id, &payloads);
    let binding = ThresholdFixtureStoreBinding::new(
        Digest::fixture(verified_stage_support::bootstrap_digest()),
        "fixture-v1",
        1,
    )
    .unwrap();
    let mut store =
        DurableFixturePromotionAuthority::create_from_in_memory(&path, binding.clone(), &memory)
            .unwrap();
    let previous = store.snapshot(&id).unwrap();
    assert_eq!(
        previous.digest.to_hex(),
        format!(
            "{:x}",
            Sha256::digest(&previous.bytes[..previous.bytes.len() - 1])
        )
    );
    let receipt = store
        .reserve_verify_signed(&id, 4, CommandId::fixture("verify"), &bundle)
        .unwrap();
    let proof = admit_prevalidated_signed_bundle(bundle, receipt, &Remote(Cell::new(0))).unwrap();
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
    drop(store);
    let reopened = DurableFixturePromotionAuthority::reopen(&path, binding).unwrap();
    let next = reopened.snapshot(&id).unwrap();
    let parsed: serde_json::Value = serde_json::from_slice(&next.bytes).unwrap();
    assert_eq!(parsed["previous_snapshot_sha256"], previous.digest.to_hex());
    std::fs::remove_file(path).unwrap();
}
