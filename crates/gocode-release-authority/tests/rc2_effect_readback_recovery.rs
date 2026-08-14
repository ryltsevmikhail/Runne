#![cfg(feature = "fixture-only")]

#[path = "rc2_effect_readback_recovery/support.rs"]
mod rc2_effect_readback_recovery_support;
use rc2_effect_readback_recovery_support::*;

#[test]
fn durable_readback_recovery_closes_only_the_exact_uncertain_slot() {
    let path = path("succeeded");
    let (memory, id, payloads) = signing_authorized();
    let mut authority = durable(&path, &memory);
    let lease = authority
        .reserve_rc2_signing_effects(&id, 4)
        .unwrap()
        .take(SLOT)
        .unwrap();
    authority.dispatch_rc2_signing_effects(&id, lease).unwrap();
    drop(authority);

    let mut authority = reopen(&path);
    let lease = authority
        .recover_rc2_signing_effects(&id)
        .unwrap()
        .take(SLOT)
        .unwrap();
    authority.uncertain_rc2_signing_effects(lease).unwrap();
    drop(authority);

    let mut authority = reopen(&path);
    let lease = authority
        .recover_rc2_signing_effects(&id)
        .unwrap()
        .take(SLOT)
        .unwrap();
    authority
        .reconcile_rc2_signing_readback(
            &id,
            lease,
            readback(&payloads, SLOT, ARTIFACT, "succeeded", 8),
        )
        .unwrap();
    drop(authority);

    let mut authority = reopen(&path);
    let other = authority
        .recover_rc2_signing_effects(&id)
        .unwrap()
        .take("linux-deb")
        .unwrap();
    authority.dispatch_rc2_signing_effects(&id, other).unwrap();
    let lease = authority
        .recover_rc2_signing_effects(&id)
        .unwrap()
        .take(SLOT)
        .unwrap();
    assert!(authority.uncertain_rc2_signing_effects(lease).is_err());
    cleanup(&path);
}

#[test]
fn absent_readback_fences_the_current_generation_without_replacement_policy() {
    let (path, mut authority, id, payloads) = uncertain_authority("absent");
    let lease = authority
        .recover_rc2_signing_effects(&id)
        .unwrap()
        .take(SLOT)
        .unwrap();
    authority
        .reconcile_rc2_signing_readback(
            &id,
            lease,
            readback(&payloads, SLOT, ARTIFACT, "absent", 8),
        )
        .unwrap();
    drop(authority);
    let mut authority = reopen(&path);
    let lease = authority
        .recover_rc2_signing_effects(&id)
        .unwrap()
        .take(SLOT)
        .unwrap();
    assert!(authority.dispatch_rc2_signing_effects(&id, lease).is_err());
    drop(authority);
    cleanup(&path);
}

#[test]
fn inconclusive_readback_stays_fenced_until_the_bounded_block() {
    let (path, mut authority, id, payloads) = uncertain_authority("inconclusive");
    let mut lease = authority
        .recover_rc2_signing_effects(&id)
        .unwrap()
        .take(SLOT)
        .unwrap();
    for _ in 0..2 {
        authority
            .reconcile_rc2_signing_readback(
                &id,
                lease,
                readback(&payloads, SLOT, ARTIFACT, "inconclusive", 8),
            )
            .unwrap();
        drop(authority);
        authority = reopen(&path);
        lease = authority
            .recover_rc2_signing_effects(&id)
            .unwrap()
            .take(SLOT)
            .unwrap();
    }
    authority
        .reconcile_rc2_signing_readback(
            &id,
            lease,
            readback(&payloads, SLOT, ARTIFACT, "inconclusive", 8),
        )
        .unwrap();
    drop(authority);
    let mut authority = reopen(&path);
    let lease = authority
        .recover_rc2_signing_effects(&id)
        .unwrap()
        .take(SLOT)
        .unwrap();
    assert!(
        authority
            .reconcile_rc2_signing_readback(
                &id,
                lease,
                readback(&payloads, SLOT, ARTIFACT, "succeeded", 8),
            )
            .is_err()
    );
    drop(authority);
    cleanup(&path);
}

#[test]
fn invalid_readback_does_not_mutate_the_durable_file() {
    let wrong = "b".repeat(64);
    for (name, slot, generation, artifact, runner, signature, wrong_authorization) in [
        ("forged", SLOT, 1, ARTIFACT, "runner", 7, false),
        ("slot", "linux-deb", 1, ARTIFACT, "runner", 8, false),
        ("authorization", SLOT, 1, ARTIFACT, "runner", 8, true),
        ("generation", SLOT, 2, ARTIFACT, "runner", 8, false),
        ("artifact", SLOT, 1, wrong.as_str(), "runner", 8, false),
        ("runner", SLOT, 1, ARTIFACT, "issuer", 10, false),
    ] {
        let (path, mut authority, id, payloads) = uncertain_authority(name);
        let authorization = authorization(&payloads);
        let authorization = if wrong_authorization {
            wrong.as_str()
        } else {
            &authorization
        };
        let lease = authority
            .recover_rc2_signing_effects(&id)
            .unwrap()
            .take(SLOT)
            .unwrap();
        let before = std::fs::read(&path).unwrap();
        assert!(
            authority
                .reconcile_rc2_signing_readback(
                    &id,
                    lease,
                    signed_readback(
                        slot,
                        authorization,
                        generation,
                        artifact,
                        "succeeded",
                        runner,
                        signature
                    ),
                )
                .is_err()
        );
        assert_eq!(std::fs::read(&path).unwrap(), before, "{name}");
        drop(authority);
        cleanup(&path);
    }
}
