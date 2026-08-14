#![cfg(feature = "fixture-only")]

use gocode_release_authority::{
    AuthenticatedThresholdTransition, AuthorityError, CommandId, Digest,
    DurableFixturePromotionAuthority, InspectedCanonicalPayload, Mutation, PromotionStore,
    ThresholdAdmission, ThresholdAdmissionRequest, ThresholdFixtureStoreBinding,
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
mod verified_stage_support;

struct Remote;

impl ThresholdVerificationContext for Remote {
    fn recover_existing(
        &self,
        _: &ThresholdAdmissionRequest<'_>,
    ) -> Result<Option<ThresholdAdmission>, AuthorityError> {
        Ok(Some(ThresholdAdmission::ExistingSame {
            admission_id: Digest::fixture([9; 32]),
        }))
    }

    fn trusted_state_and_now(&self) -> Result<(ThresholdVerificationState, u64), AuthorityError> {
        unreachable!()
    }

    fn persist_new(
        &self,
        _: AuthenticatedThresholdTransition,
    ) -> Result<ThresholdAdmission, AuthorityError> {
        Ok(ThresholdAdmission::NewlyAdmitted {
            admission_id: Digest::fixture([9; 32]),
        })
    }

    fn acknowledge_or_recover(
        &self,
        request: &gocode_release_authority::ThresholdAckRequest<'_>,
    ) -> Result<gocode_release_authority::ThresholdAckProof, AuthorityError> {
        Ok(request.acknowledge())
    }
}

#[test]
fn completed_stage_commands_require_exact_durable_claims_after_reopen() {
    let path = std::path::Path::new("/dev/shm")
        .join(format!("gocode-stage-claim-replay-{}", std::process::id()));
    cleanup(&path);
    let (mut memory, id, payloads) = signing_support::signing_authorized();
    let binding = binding();
    let bundle = signing_support::leased_bundle(&mut memory, &id, &payloads);
    advance_to_rc3_review(&mut memory, &id, bundle);
    let mut authority =
        DurableFixturePromotionAuthority::create_from_in_memory(&path, binding.clone(), &memory)
            .unwrap();
    legacy_publication_ingress_is_superseded(&mut authority, &id, &payloads);
    drop(authority);
    let source = std::fs::read_to_string(&path).unwrap();
    drop(DurableFixturePromotionAuthority::reopen(&path, binding.clone()).unwrap());
    for mutate in [
        delete_rc1_claim as fn(&str) -> String,
        substitute_nonce,
        substitute_fingerprint,
        add_extra_claim,
        remove_admission,
        delete_admission,
    ] {
        std::fs::write(&path, mutate(&source)).unwrap();
        assert!(DurableFixturePromotionAuthority::reopen(&path, binding.clone()).is_err());
    }
    cleanup(&path);
}

#[test]
fn legacy_rc3_publication_is_superseded_before_and_after_reopen_without_mutation() {
    let path = path();
    cleanup(&path);
    let (mut memory, id, payloads) = signing_support::signing_authorized();
    let bundle = signing_support::leased_bundle(&mut memory, &id, &payloads);
    advance_to_rc3_review(&mut memory, &id, bundle);
    let mut authority =
        DurableFixturePromotionAuthority::create_from_in_memory(&path, binding(), &memory).unwrap();
    let before = std::fs::read(&path).unwrap();
    legacy_publication_ingress_is_superseded(&mut authority, &id, &payloads);
    drop(authority);
    let mut authority = DurableFixturePromotionAuthority::reopen(&path, binding()).unwrap();
    assert_eq!(std::fs::read(&path).unwrap(), before);
    legacy_publication_ingress_is_superseded(&mut authority, &id, &payloads);
    drop(authority);
    assert_eq!(std::fs::read(&path).unwrap(), before);
    cleanup(&path);
}

fn advance_to_rc3_review(
    store: &mut gocode_release_authority::InMemoryPromotionStore,
    id: &gocode_release_authority::PromotionId,
    bundle: gocode_release_authority::FixturePrevalidatedSignedBundle,
) {
    let receipt = store
        .reserve_verify_signed(id, 4, CommandId::fixture("verify"), &bundle)
        .unwrap();
    let proof = admit_prevalidated_signed_bundle(bundle, receipt, &Remote).unwrap();
    store
        .transact(
            id,
            4,
            CommandId::fixture("verify"),
            Mutation::VerifySigned {
                proof: Box::new(proof),
            },
        )
        .unwrap();
    store
        .acknowledge_threshold_completion(id, 5, CommandId::fixture("ack"), &Remote)
        .unwrap();
    store
        .transact(id, 6, CommandId::fixture("r3"), Mutation::StartRc3Review {})
        .unwrap();
}

fn legacy_publication_ingress_is_superseded(
    authority: &mut DurableFixturePromotionAuthority,
    id: &gocode_release_authority::PromotionId,
    payloads: &[(gocode_release_authority::CanonicalPayloadKind, Vec<u8>)],
) {
    let manifest = manifest(payloads);
    assert_eq!(manifest, Err(AuthorityError::AuthorityVersionSuperseded));
    let [_, _, rc3] = verified_stage_support::verified_stages(payloads);
    assert_eq!(
        rc3.raw().commit(
            authority,
            id,
            7,
            CommandId::fixture("publish"),
            gocode_release_authority::CanonicalPayloadKind::Rc3Authorization,
        ),
        Err(AuthorityError::AuthorityVersionSuperseded)
    );
}

fn manifest(
    payloads: &[(gocode_release_authority::CanonicalPayloadKind, Vec<u8>)],
) -> Result<InspectedCanonicalPayload, AuthorityError> {
    payloads
        .iter()
        .find(|(kind, _)| {
            *kind == gocode_release_authority::CanonicalPayloadKind::PublicationManifest
        })
        .map(|(kind, bytes)| InspectedCanonicalPayload::parse(*kind, bytes))
        .unwrap()
}

fn delete_rc1_claim(source: &str) -> String {
    let start = source.find("{\"nonce\":\"release-50\"").unwrap();
    let end = source[start..].find("},").unwrap() + start + 2;
    format!("{}{}", &source[..start], &source[end..])
}

fn substitute_nonce(source: &str) -> String {
    source.replacen("\"nonce\":\"release-50\"", "\"nonce\":\"replacement\"", 1)
}

fn substitute_fingerprint(source: &str) -> String {
    source.replacen(
        "\"fingerprint\":\"bc8c9f5565b4ca935fc6c139596f9d6644fb80346fb0a0b0025c4f3fd698191d\"",
        "\"fingerprint\":\"ac8c9f5565b4ca935fc6c139596f9d6644fb80346fb0a0b0025c4f3fd698191d\"",
        1,
    )
}

fn add_extra_claim(source: &str) -> String {
    let mut wire: serde_json::Value = serde_json::from_str(source).unwrap();
    let claims = wire["promotions"][0]["record"]["stage_claims"]
        .as_array_mut()
        .unwrap();
    let mut extra = claims[0].clone();
    extra["nonce"] = "extra".into();
    claims.push(extra);
    serde_json::to_string(&wire).unwrap() + "\n"
}

fn remove_admission(source: &str) -> String {
    let mut wire: serde_json::Value = serde_json::from_str(source).unwrap();
    wire["promotions"][0]["record"]["admission"] = serde_json::Value::Null;
    serde_json::to_string(&wire).unwrap() + "\n"
}

fn delete_admission(source: &str) -> String {
    let mut wire: serde_json::Value = serde_json::from_str(source).unwrap();
    wire["promotions"][0]["record"]
        .as_object_mut()
        .unwrap()
        .remove("admission");
    serde_json::to_string(&wire).unwrap() + "\n"
}

fn binding() -> ThresholdFixtureStoreBinding {
    ThresholdFixtureStoreBinding::new(
        Digest::fixture(verified_stage_support::bootstrap_digest()),
        "fixture-v1",
        1,
    )
    .unwrap()
}

fn path() -> std::path::PathBuf {
    std::path::Path::new("/dev/shm").join(format!(
        "gocode-stage-claim-bijection-{}",
        std::process::id()
    ))
}

fn cleanup(path: &std::path::Path) {
    let _ = std::fs::remove_file(path);
    let _ = std::fs::remove_file(path.with_extension("lease"));
}
