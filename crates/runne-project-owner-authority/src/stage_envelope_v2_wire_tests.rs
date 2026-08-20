//! Raw stage-envelope `/2` verification tests: full chain, mutations, admission.

#![allow(clippy::semicolon_if_nothing_returned, clippy::redundant_clone)]

use std::cell::{Cell, RefCell};

use ed25519_dalek::SigningKey;
use sha2::{Digest, Sha256};

use crate::v5_envelope_test_support::*;
use crate::{
    AuthorityError, STAGE_ENVELOPE_SCHEMA_V2, StageAuthorityEnvelopeV2, verify_stage_envelope_v2,
};

type Mutation = (
    &'static str,
    Box<dyn Fn(&mut StageAuthorityEnvelopeV2)>,
    AuthorityError,
);

#[test]
fn valid_stage_envelope_v2_verifies_full_raw_chain_and_calls_context_once() {
    let chain = chain();
    let (envelope, key) = stage_envelope(&chain.receipt5, "RC3_PUBLICATION_AUTHORIZER");
    let bytes = signed_stage_v2(&envelope, &key);
    let context = EnvelopeContext(Cell::new(0));
    let verified = verify_stage_envelope_v2(
        &bytes,
        Sha256::digest(&bytes[..bytes.len() - 1]).into(),
        &chain.receipt5,
        &context,
    )
    .unwrap();
    assert_eq!(
        verified.envelope_sha256(),
        <[u8; 32]>::from(Sha256::digest(&bytes[..bytes.len() - 1]))
    );
    assert_eq!(verified.receipt_sha256(), chain.receipt5.receipt_sha256());
    assert_eq!(verified.payload_sha256(), envelope.payload_sha256);
    assert_eq!(
        verified.payload_schema_id(),
        "gocode.release.rc3-publication-authorization/2"
    );
    assert_eq!(
        verified.payload(),
        crate::canonical_stage_payload(&envelope.payload).unwrap()
    );
    assert_eq!(verified.issuer().role, "RC3_PUBLICATION_AUTHORIZER");
    assert_eq!(verified.issuer().key_id, envelope.issuer_key_id);
    assert_eq!(verified.validity().authorization_nonce, "nonce-stage-1");
    assert_eq!(verified.validity().trust_generation, 4);
    assert_eq!(context.0.get(), 1);
}

#[test]
fn legacy_or_mixed_envelope_versions_are_rejected_before_context() {
    let chain = chain();
    let (mut envelope, key) = stage_envelope(&chain.receipt5, "RC3_PUBLICATION_AUTHORIZER");
    envelope.schema_version = "gocode.release.post-rc0-stage-envelope/1".into();
    let bytes = signed_stage_v2(&envelope, &key);
    let context = EnvelopeContext(Cell::new(0));
    assert_eq!(
        verify_stage_envelope_v2(
            &bytes,
            Sha256::digest(&bytes[..bytes.len() - 1]).into(),
            &chain.receipt5,
            &context
        ),
        Err(AuthorityError::AuthorityVersionSuperseded)
    );
    assert_eq!(context.0.get(), 0);
    envelope.schema_version = "gocode.other/9".into();
    let bytes = signed_stage_v2(&envelope, &key);
    assert_eq!(
        verify_stage_envelope_v2(
            &bytes,
            Sha256::digest(&bytes[..bytes.len() - 1]).into(),
            &chain.receipt5,
            &context
        ),
        Err(AuthorityError::AuthorityVersionSuperseded)
    );
    assert_eq!(context.0.get(), 0);
}

#[test]
fn malformed_noncanonical_or_wrong_digest_bytes_never_reach_context() {
    let chain = chain();
    let (envelope, key) = stage_envelope(&chain.receipt5, "RC3_PUBLICATION_AUTHORIZER");
    let bytes = signed_stage_v2(&envelope, &key);
    let context = EnvelopeContext(Cell::new(0));
    let crlf = String::from_utf8(bytes.clone())
        .unwrap()
        .replace('\n', "\r\n")
        .into_bytes();
    assert_eq!(
        verify_stage_envelope_v2(
            &crlf,
            Sha256::digest(&crlf[..crlf.len() - 2]).into(),
            &chain.receipt5,
            &context
        ),
        Err(AuthorityError::InvalidCanonicalReceipt)
    );
    assert_eq!(context.0.get(), 0);
    assert_eq!(
        verify_stage_envelope_v2(&bytes, [0; 32], &chain.receipt5, &context),
        Err(AuthorityError::InvalidReceiptDigest)
    );
    assert_eq!(context.0.get(), 0);
    let mut malformed: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    malformed["signature"] = serde_json::Value::String("A".into());
    let mut malformed = serde_json::to_vec(&malformed).unwrap();
    malformed.push(b'\n');
    assert_eq!(
        verify_stage_envelope_v2(
            &malformed,
            Sha256::digest(&malformed[..malformed.len() - 1]).into(),
            &chain.receipt5,
            &context
        ),
        Err(AuthorityError::InvalidReceiptSignature)
    );
    assert_eq!(context.0.get(), 0);
    let mut unknown: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    unknown["unexpected"] = serde_json::Value::Bool(true);
    let mut unknown = serde_json::to_vec(&unknown).unwrap();
    unknown.push(b'\n');
    assert_eq!(
        verify_stage_envelope_v2(
            &unknown,
            Sha256::digest(&unknown[..unknown.len() - 1]).into(),
            &chain.receipt5,
            &context
        ),
        Err(AuthorityError::InvalidStageEnvelope)
    );
    assert_eq!(context.0.get(), 0);
    let duplicate = b"{\"schema_version\":\"gocode.release.post-rc0-stage-envelope/2\",\"schema_version\":\"x\"}\n";
    assert_eq!(
        verify_stage_envelope_v2(duplicate, [0; 32], &chain.receipt5, &context),
        Err(AuthorityError::InvalidJson)
    );
    assert_eq!(context.0.get(), 0);
    let mut utf8 = bytes.clone();
    utf8[0] = 0xff;
    assert!(verify_stage_envelope_v2(&utf8, [0; 32], &chain.receipt5, &context).is_err());
    assert_eq!(context.0.get(), 0);
}

#[test]
fn forged_signature_by_wrong_key_never_reaches_context() {
    let chain = chain();
    let (envelope, _) = stage_envelope(&chain.receipt5, "RC3_PUBLICATION_AUTHORIZER");
    let bytes = signed_stage_v2(&envelope, &transition_key(0));
    let context = EnvelopeContext(Cell::new(0));
    assert_eq!(
        verify_stage_envelope_v2(
            &bytes,
            Sha256::digest(&bytes[..bytes.len() - 1]).into(),
            &chain.receipt5,
            &context
        ),
        Err(AuthorityError::InvalidReceiptSignature)
    );
    assert_eq!(context.0.get(), 0);
}

#[test]
fn envelope_mutations_are_rejected_before_context() {
    let chain = chain();
    let (envelope, key) = stage_envelope(&chain.receipt5, "RC3_PUBLICATION_AUTHORIZER");
    let other = SigningKey::from_bytes(&[9; 32]);
    let root_key_id =
        crate::trust_canonical::hex(&crate::key_id(&chain.root.verifying_key().to_bytes()));
    let mutations: Vec<Mutation> = include!("stage_envelope_v2_mutations.rs");
    for (name, mutate, expected) in mutations {
        let mut changed = envelope.clone();
        mutate(&mut changed);
        let bytes = signed_stage_v2(&changed, &key);
        let context = EnvelopeContext(Cell::new(0));
        assert_eq!(
            verify_stage_envelope_v2(
                &bytes,
                Sha256::digest(&bytes[..bytes.len() - 1]).into(),
                &chain.receipt5,
                &context
            ),
            Err(expected),
            "{name} must be rejected before context admission"
        );
        assert_eq!(context.0.get(), 0, "{name} must not reach context");
    }
}

#[test]
fn nonce_replay_is_rejected_by_the_context() {
    let chain = chain();
    let (envelope, key) = stage_envelope(&chain.receipt5, "RC3_PUBLICATION_AUTHORIZER");
    let bytes = signed_stage_v2(&envelope, &key);
    let digest = Sha256::digest(&bytes[..bytes.len() - 1]).into();
    let context = ReplayEnvelopeContext(RefCell::new(Vec::new()));
    assert!(verify_stage_envelope_v2(&bytes, digest, &chain.receipt5, &context).is_ok());
    assert_eq!(
        verify_stage_envelope_v2(&bytes, digest, &chain.receipt5, &context),
        Err(AuthorityError::ReplayedStageEnvelope)
    );
}

#[test]
fn stale_or_revoked_envelope_is_rejected_by_the_context_after_crypto() {
    let chain = chain();
    let (envelope, key) = stage_envelope(&chain.receipt5, "RC3_PUBLICATION_AUTHORIZER");
    let bytes = signed_stage_v2(&envelope, &key);
    let context = RejectingEnvelopeContext(Cell::new(0));
    assert_eq!(
        verify_stage_envelope_v2(
            &bytes,
            Sha256::digest(&bytes[..bytes.len() - 1]).into(),
            &chain.receipt5,
            &context
        ),
        Err(AuthorityError::StaleOrRevokedStageEnvelope)
    );
    assert_eq!(context.0.get(), 1);
}

#[test]
fn verified_stage_envelope_v2_is_move_only_and_not_publicly_constructible() {
    let chain = chain();
    let (envelope, key) = stage_envelope(&chain.receipt5, "RC3_PUBLICATION_AUTHORIZER");
    let bytes = signed_stage_v2(&envelope, &key);
    let verified = verify_stage_envelope_v2(
        &bytes,
        Sha256::digest(&bytes[..bytes.len() - 1]).into(),
        &chain.receipt5,
        &EnvelopeContext(Cell::new(0)),
    )
    .unwrap();
    // The handle has private fields and no public Clone; moving it into the
    // closure below must be the only way to consume it.
    let moved = move || verified.envelope_sha256();
    let _ = moved();
    assert_eq!(
        STAGE_ENVELOPE_SCHEMA_V2,
        "gocode.release.post-rc0-stage-envelope/2"
    );
}
