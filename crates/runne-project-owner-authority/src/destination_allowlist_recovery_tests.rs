use std::cell::Cell;

use sha2::{Digest, Sha256};

use crate::v5_envelope_test_support::*;
use crate::{
    AuthorityError, DESTINATION_ALLOWLIST_SCHEMA_V1, PublicationDestinationAllowlistV1,
    verify_destination_allowlist_v1,
};

type Mutation = (
    &'static str,
    Box<dyn Fn(&mut PublicationDestinationAllowlistV1)>,
);

#[test]
fn allowlist_grammar_violations_are_rejected_even_with_matching_instance_binding() {
    let chain = chain();
    let allowlist = allowlist(&chain.trust);
    let mutations: Vec<Mutation> = vec![
        (
            "empty destination",
            Box::new(|item| item.destinations[0].destination = String::new()),
        ),
        (
            "uppercase destination",
            Box::new(|item| item.destinations[0].destination = "BAD".into()),
        ),
        (
            "space destination",
            Box::new(|item| item.destinations[0].destination = "has space".into()),
        ),
        (
            "empty channel",
            Box::new(|item| item.destinations[0].channel = String::new()),
        ),
        (
            "uppercase effect kind",
            Box::new(|item| item.destinations[0].permitted_effect_kinds = vec!["NOTIFY".into()]),
        ),
        (
            "unsorted effect kinds",
            Box::new(|item| {
                item.destinations[0].permitted_effect_kinds =
                    vec!["upload".into(), "notify".into()];
            }),
        ),
        (
            "duplicate effect kinds",
            Box::new(|item| {
                item.destinations[0].permitted_effect_kinds =
                    vec!["notify".into(), "notify".into()];
            }),
        ),
        (
            "empty effect kinds",
            Box::new(|item| item.destinations[0].permitted_effect_kinds.clear()),
        ),
        (
            "unsafe policy id",
            Box::new(|item| item.policy_id = "unsafe/slash".into()),
        ),
    ];
    for (name, mutate) in mutations {
        let mut changed = allowlist.clone();
        mutate(&mut changed);
        let bound =
            Sha256::digest(crate::canonical_unsigned_allowlist_v1(&changed).unwrap()).into();
        let receipt5 = allowlist_receipt5(&chain.root, &chain.trust, bound);
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
            "{name} must be rejected by grammar even with a matching binding"
        );
        assert_eq!(context.0.get(), 0, "{name} must not reach context");
    }
}

#[test]
fn allowlist_context_rejection_is_propagated_after_crypto() {
    let chain = chain();
    let allowlist = allowlist(&chain.trust);
    let bound = Sha256::digest(crate::canonical_unsigned_allowlist_v1(&allowlist).unwrap()).into();
    let receipt5 = allowlist_receipt5(&chain.root, &chain.trust, bound);
    let bytes = signed_allowlist_v1(&allowlist, &chain.root);
    let context = RejectingAllowlistContext(Cell::new(0));
    assert_eq!(
        verify_destination_allowlist_v1(
            &bytes,
            Sha256::digest(&bytes[..bytes.len() - 1]).into(),
            &chain.trust,
            &receipt5,
            &context
        ),
        Err(AuthorityError::StaleOrRevokedPromotionBootstrap)
    );
    assert_eq!(context.0.get(), 1);
}

#[test]
fn verified_allowlist_is_move_only_and_rejects_divergent_recovery() {
    let chain = chain();
    let allowlist = allowlist(&chain.trust);
    let bound = Sha256::digest(crate::canonical_unsigned_allowlist_v1(&allowlist).unwrap()).into();
    let receipt5 = allowlist_receipt5(&chain.root, &chain.trust, bound);
    let bytes = signed_allowlist_v1(&allowlist, &chain.root);
    let digest = Sha256::digest(&bytes[..bytes.len() - 1]).into();
    let context = AllowlistContext(Cell::new(0));
    let verified =
        verify_destination_allowlist_v1(&bytes, digest, &chain.trust, &receipt5, &context).unwrap();
    assert_eq!(consume_verified(verified), 1);
    assert_eq!(context.0.get(), 1);
    let mut divergent = allowlist;
    divergent.generation = 2;
    let bytes = signed_allowlist_v1(&divergent, &chain.root);
    let context = AllowlistContext(Cell::new(0));
    assert_eq!(
        verify_destination_allowlist_v1(
            &bytes,
            Sha256::digest(&bytes[..bytes.len() - 1]).into(),
            &chain.trust,
            &receipt5,
            &context
        ),
        Err(AuthorityError::InvalidDestinationAllowlist)
    );
    assert_eq!(context.0.get(), 0);
    assert_eq!(
        DESTINATION_ALLOWLIST_SCHEMA_V1,
        "runne.project-owner.publication-destination-allowlist/1"
    );
}

fn consume_verified(value: crate::VerifiedDestinationAllowlist) -> u64 {
    let generation = value.generation();
    drop(value);
    generation
}
