//! Root-signed destination-allowlist `/1` verification tests.

#![allow(clippy::semicolon_if_nothing_returned, clippy::redundant_clone)]

use std::cell::Cell;

use ed25519_dalek::SigningKey;
use sha2::{Digest, Sha256};

use crate::v5_envelope_test_support::*;
use crate::{
    AuthorityError, PublicationDestinationAllowlistV1, PublicationDestinationV1,
    verify_destination_allowlist_v1,
};

type Mutation = (
    &'static str,
    Box<dyn Fn(&mut PublicationDestinationAllowlistV1)>,
);

#[test]
fn valid_allowlist_v1_verifies_against_root_trust_and_receipt_bindings() {
    let chain = chain();
    let allowlist = allowlist(&chain.trust);
    let unsigned = crate::canonical_unsigned_allowlist_v1(&allowlist).unwrap();
    let bound = Sha256::digest(&unsigned).into();
    let receipt5 = allowlist_receipt5(&chain.root, &chain.trust, bound);
    let bytes = signed_allowlist_v1(&allowlist, &chain.root);
    let context = AllowlistContext(Cell::new(0));
    let verified = verify_destination_allowlist_v1(
        &bytes,
        Sha256::digest(&bytes[..bytes.len() - 1]).into(),
        &chain.trust,
        &receipt5,
        &context,
    )
    .unwrap();
    assert_eq!(
        verified.digest(),
        <[u8; 32]>::from(Sha256::digest(&bytes[..bytes.len() - 1]))
    );
    assert_eq!(verified.generation(), 1);
    assert_eq!(verified.policy_id(), "rc3-publication-policy");
    assert_eq!(verified.key_id(), &allowlist.key_id);
    assert_eq!(verified.key_epoch(), 4);
    assert_eq!(verified.destinations().len(), 1);
    assert_eq!(verified.destinations()[0].destination, "github");
    assert_eq!(
        verified.destinations()[0].permitted_effect_kinds,
        ["notify", "upload"]
    );
    assert_eq!(context.0.get(), 1);
}

#[test]
fn legacy_or_mixed_allowlist_versions_are_rejected_before_context() {
    let chain = chain();
    let allowlist = allowlist(&chain.trust);
    let bound = Sha256::digest(crate::canonical_unsigned_allowlist_v1(&allowlist).unwrap()).into();
    let receipt5 = allowlist_receipt5(&chain.root, &chain.trust, bound);
    for version in [
        "gocode.project-owner.publication-destination-allowlist/2",
        "gocode.other/1",
    ] {
        let mut changed = allowlist.clone();
        changed.schema_version = version.into();
        let bytes = signed_allowlist_v1(&changed, &chain.root);
        let context = AllowlistContext(Cell::new(0));
        assert_eq!(
            verify_destination_allowlist_v1(
                &bytes,
                Sha256::digest(&bytes[..bytes.len() - 1]).into(),
                &chain.trust,
                &receipt5,
                &context
            ),
            Err(AuthorityError::AuthorityVersionSuperseded)
        );
        assert_eq!(context.0.get(), 0);
    }
}

#[test]
fn malformed_wrong_digest_or_forged_bytes_never_reach_context() {
    let chain = chain();
    let allowlist = allowlist(&chain.trust);
    let bound = Sha256::digest(crate::canonical_unsigned_allowlist_v1(&allowlist).unwrap()).into();
    let receipt5 = allowlist_receipt5(&chain.root, &chain.trust, bound);
    let bytes = signed_allowlist_v1(&allowlist, &chain.root);
    let context = AllowlistContext(Cell::new(0));
    let crlf = String::from_utf8(bytes.clone())
        .unwrap()
        .replace('\n', "\r\n")
        .into_bytes();
    assert_eq!(
        verify_destination_allowlist_v1(
            &crlf,
            Sha256::digest(&crlf[..crlf.len() - 2]).into(),
            &chain.trust,
            &receipt5,
            &context
        ),
        Err(AuthorityError::InvalidCanonicalReceipt)
    );
    assert_eq!(context.0.get(), 0);
    assert_eq!(
        verify_destination_allowlist_v1(&bytes, [0; 32], &chain.trust, &receipt5, &context),
        Err(AuthorityError::InvalidReceiptDigest)
    );
    assert_eq!(context.0.get(), 0);
    let forged = signed_allowlist_v1(&allowlist, &SigningKey::from_bytes(&[9; 32]));
    assert_eq!(
        verify_destination_allowlist_v1(
            &forged,
            Sha256::digest(&forged[..forged.len() - 1]).into(),
            &chain.trust,
            &receipt5,
            &context
        ),
        Err(AuthorityError::InvalidReceiptSignature)
    );
    assert_eq!(context.0.get(), 0);
}

#[test]
#[expect(
    clippy::too_many_lines,
    reason = "one adversarial allowlist mutation matrix"
)]
fn allowlist_mutations_are_rejected_before_context_against_fixed_bindings() {
    let chain = chain();
    let allowlist = allowlist(&chain.trust);
    let bound = Sha256::digest(crate::canonical_unsigned_allowlist_v1(&allowlist).unwrap()).into();
    let receipt5 = allowlist_receipt5(&chain.root, &chain.trust, bound);
    let other = SigningKey::from_bytes(&[9; 32]);
    let other_key_id =
        crate::trust_canonical::hex(&crate::key_id(&other.verifying_key().to_bytes()));
    let mutations: Vec<Mutation> = vec![
        (
            "repository",
            Box::new(move |item| item.repository_id = "other".into()),
        ),
        (
            "root key id",
            Box::new(move |item| item.key_id = other_key_id.clone()),
        ),
        ("root key epoch", Box::new(move |item| item.key_epoch = 3)),
        (
            "generation divergence",
            Box::new(move |item| item.generation = 2),
        ),
        (
            "policy id",
            Box::new(move |item| item.policy_id = "unsafe/slash".into()),
        ),
        (
            "destination grammar",
            Box::new(move |item| item.destinations[0].destination = "BAD".into()),
        ),
        (
            "channel grammar",
            Box::new(move |item| item.destinations[0].channel = "bad channel".into()),
        ),
        (
            "effect kinds unsorted",
            Box::new(move |item| {
                item.destinations[0].permitted_effect_kinds = vec!["upload".into(), "notify".into()]
            }),
        ),
        (
            "effect kinds duplicate",
            Box::new(move |item| {
                item.destinations[0].permitted_effect_kinds = vec!["notify".into(), "notify".into()]
            }),
        ),
        (
            "effect kinds empty",
            Box::new(move |item| item.destinations[0].permitted_effect_kinds.clear()),
        ),
        (
            "executor policy digest",
            Box::new(move |item| item.destinations[0].executor_policy_sha256 = [8; 32]),
        ),
        (
            "unordered expiry",
            Box::new(move |item| item.expires_at = item.not_before.clone()),
        ),
        (
            "zero revocation",
            Box::new(move |item| item.revocation_epoch = 0),
        ),
        (
            "duplicate destination",
            Box::new(move |item| {
                item.destinations.push(PublicationDestinationV1 {
                    destination: "github".into(),
                    channel: "release-notes".into(),
                    permitted_effect_kinds: vec!["notify".into()],
                    executor_policy_sha256: [7; 32],
                })
            }),
        ),
        (
            "unsorted destination",
            Box::new(move |item| {
                item.destinations.push(PublicationDestinationV1 {
                    destination: "aaa".into(),
                    channel: "release-notes".into(),
                    permitted_effect_kinds: vec!["notify".into()],
                    executor_policy_sha256: [7; 32],
                })
            }),
        ),
        (
            "empty destinations",
            Box::new(move |item| item.destinations.clear()),
        ),
    ];
    for (name, mutate) in mutations {
        let mut changed = allowlist.clone();
        mutate(&mut changed);
        let bytes = signed_allowlist_v1(&changed, &chain.root);
        let context = AllowlistContext(Cell::new(0));
        assert_eq!(
            verify_destination_allowlist_v1(
                &bytes,
                Sha256::digest(&bytes[..bytes.len() - 1]).into(),
                &chain.trust,
                &receipt5,
                &context
            ),
            Err(AuthorityError::InvalidDestinationAllowlist),
            "{name} must be rejected before context admission"
        );
        assert_eq!(context.0.get(), 0, "{name} must not reach context");
    }
}
