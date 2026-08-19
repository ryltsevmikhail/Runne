#![cfg(feature = "fixture-only")]

use runne_release_authority::{
    AuthenticatedThresholdTransition, AuthorityError, CanonicalPayloadKind, CommandId, Digest,
    FixturePrevalidatedSignedBundle, InMemoryPromotionStore, PromotionId, PromotionStore,
    ThresholdAdmission, ThresholdAdmissionRequest, ThresholdVerificationContext,
    ThresholdVerificationState, admit_prevalidated_signed_bundle,
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
struct Context {
    frozen: bool,
    now: u64,
    channel_policy_id: Option<&'static str>,
}
impl ThresholdVerificationContext for Context {
    fn recover_existing(
        &self,
        _: &ThresholdAdmissionRequest<'_>,
    ) -> Result<Option<ThresholdAdmission>, AuthorityError> {
        Ok(None)
    }
    fn trusted_state_and_now(&self) -> Result<(ThresholdVerificationState, u64), AuthorityError> {
        Ok((
            ThresholdVerificationState {
                versions: ["root", "targets", "snapshot", "timestamp"]
                    .into_iter()
                    .map(|role| (role.into(), 1))
                    .collect(),
                rollback_floor: 1,
                revocation_floor: 1,
                frozen: self.frozen,
                generation: 9,
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
                channel_policy_id: self.channel_policy_id.map(str::to_owned),
                role_bodies: std::collections::BTreeMap::new(),
                role_digests: std::collections::BTreeMap::new(),
            },
            self.now,
        ))
    }
    fn persist_new(
        &self,
        _: AuthenticatedThresholdTransition,
    ) -> Result<ThresholdAdmission, AuthorityError> {
        Ok(ThresholdAdmission::NewlyAdmitted {
            admission_id: Digest::fixture([8; 32]),
        })
    }
    fn acknowledge_or_recover(
        &self,
        request: &runne_release_authority::ThresholdAckRequest<'_>,
    ) -> Result<runne_release_authority::ThresholdAckProof, AuthorityError> {
        Ok(request.acknowledge())
    }
}

#[test]
fn trusted_freeze_and_expiry_are_rechecked_inside_atomic_admission() {
    for context in [
        Context {
            frozen: true,
            now: 1,
            channel_policy_id: Some("fixture-channel-policy"),
        },
        Context {
            frozen: false,
            now: 2,
            channel_policy_id: Some("fixture-channel-policy"),
        },
    ] {
        let (mut store, id, bundle) = reserved();
        let receipt = store
            .reserve_verify_signed(&id, 4, CommandId::fixture("verify"), &bundle)
            .unwrap();
        assert_eq!(
            admit_prevalidated_signed_bundle(bundle, receipt, &context),
            Err(AuthorityError::BindingMismatch)
        );
    }
}

#[test]
fn unresolved_channel_requires_an_authenticated_policy_context() {
    let (mut store, id, bundle) = reserved();
    let receipt = store
        .reserve_verify_signed(&id, 4, CommandId::fixture("verify"), &bundle)
        .unwrap();
    let context = Context {
        frozen: false,
        now: 1,
        channel_policy_id: None,
    };
    assert_eq!(
        admit_prevalidated_signed_bundle(bundle, receipt, &context),
        Err(AuthorityError::BindingMismatch)
    );
}

#[test]
fn targets_bind_post_sign_records_not_rc1_pre_sign_artifacts() {
    let (_, _, payloads) = signing_support::signing_authorized();
    let manifest: serde_json::Value = serde_json::from_slice(
        &payloads
            .iter()
            .find(|(kind, _)| *kind == CanonicalPayloadKind::UnsignedManifest)
            .unwrap()
            .1,
    )
    .unwrap();
    let record: serde_json::Value = serde_json::from_slice(
        &payloads
            .iter()
            .find(|(kind, _)| *kind == CanonicalPayloadKind::ArtifactRecord)
            .unwrap()
            .1,
    )
    .unwrap();
    assert_ne!(
        manifest["artifacts"][0]["artifact_sha256"],
        record["artifact_sha256"]
    );
    assert_ne!(
        manifest["artifacts"][0]["byte_length"],
        record["artifact_length"]
    );
    let normal = signing_support::try_bundle(&payloads);
    assert!(normal.is_ok(), "{normal:?}");
    assert_eq!(
        signing_support::try_bundle(&admission_support::with_pre_sign_metadata_targets(payloads)),
        Err(AuthorityError::BindingMismatch)
    );
}

fn reserved() -> (
    InMemoryPromotionStore,
    PromotionId,
    FixturePrevalidatedSignedBundle,
) {
    let (mut store, id, payloads) = signing_support::signing_authorized();
    let bundle = signing_support::leased_bundle(&mut store, &id, &payloads);
    (store, id, bundle)
}
