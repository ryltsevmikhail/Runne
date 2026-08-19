use super::*;
use runne_release_authority::PromotionStore;

#[test]
fn foreign_cross_promotion_bundle_rejects_without_reserving_local_effects() {
    let (mut local, local_id, local_payloads) = signing_support::signing_authorized_with("local");
    let (mut foreign, foreign_id, foreign_payloads) =
        signing_support::signing_authorized_with("foreign");
    let foreign_bundle =
        signing_support::leased_bundle(&mut foreign, &foreign_id, &foreign_payloads);

    assert!(local.rc2_effect_claims().is_empty());
    assert_eq!(
        local.reserve_verify_signed(&local_id, 4, CommandId::fixture("verify"), &foreign_bundle),
        Err(AuthorityError::BindingMismatch)
    );
    assert!(local.rc2_effect_claims().is_empty());

    let local_bundle = signing_support::leased_bundle(&mut local, &local_id, &local_payloads);
    assert!(
        local
            .reserve_verify_signed(&local_id, 4, CommandId::fixture("verify"), &local_bundle)
            .is_ok()
    );
}

#[test]
fn exact_durable_authority_reopen_retains_its_instance_identity() {
    let path = path("authority-instance-reopen");
    cleanup(&path);
    let (memory, _, _) = signing_support::rc1_review_with("instance");
    let authority =
        DurableFixturePromotionAuthority::create_from_in_memory(&path, binding(), &memory).unwrap();
    drop(authority);

    assert!(DurableFixturePromotionAuthority::reopen(&path, binding()).is_ok());
    cleanup(&path);
}

#[test]
fn authority_reopen_rejects_tampered_instance_identity() {
    let path = path("authority-instance-tamper");
    cleanup(&path);
    let (memory, _, _) = signing_support::rc1_review_with("instance-tamper");
    let authority =
        DurableFixturePromotionAuthority::create_from_in_memory(&path, binding(), &memory).unwrap();
    drop(authority);
    let mut bytes = std::fs::read(&path).unwrap();
    let prefix = b"\"authority_instance\":\"";
    let offset = bytes
        .windows(prefix.len())
        .position(|window| window == prefix)
        .unwrap()
        + prefix.len();
    bytes[offset] = if bytes[offset] == b'a' { b'b' } else { b'a' };
    std::fs::write(&path, bytes).unwrap();
    assert!(DurableFixturePromotionAuthority::reopen(&path, binding()).is_err());
    cleanup(&path);
}

#[test]
fn authority_reopen_rejects_claim_and_trust_tampering() {
    for (index, (needle, replacement)) in [
        ("\"promotion\":\"integrity\"", "\"promotion\":\"other\""),
        ("\"root_epoch\":1", "\"root_epoch\":0"),
        (
            "\"stage_trust_root_epoch\":1",
            "\"stage_trust_root_epoch\":0",
        ),
    ]
    .into_iter()
    .enumerate()
    {
        let path = path(&format!("integrity-{index}"));
        cleanup(&path);
        let (memory, id, payloads) = signing_support::rc1_review_with("integrity");
        let mut authority =
            DurableFixturePromotionAuthority::create_from_in_memory(&path, binding(), &memory)
                .unwrap();
        let [stage, _, _] = verified_stage_support::verified_stages(&payloads);
        stage
            .commit(&mut authority, &id, 2, CommandId::fixture("qualify"))
            .unwrap();
        drop(authority);
        replace_after(&path, "\"stage_claims\"", needle, replacement);
        assert!(DurableFixturePromotionAuthority::reopen(&path, binding()).is_err());
        cleanup(&path);
    }
}

#[test]
fn authority_reopen_rejects_noncanonical_restored_stage_identities() {
    for (index, (needle, replacement)) in [
        (
            "\"principal\":\"principal-1\"",
            "\"principal\":\"unsafe/root\"",
        ),
        (
            "\"key\":\"02de78b83aeb9806cdf9d8221980f999de3628cf2fc3be26c220423371861df9\"",
            "\"key\":\"A2de78b83aeb9806cdf9d8221980f999de3628cf2fc3be26c220423371861df9\"",
        ),
    ]
    .into_iter()
    .enumerate()
    {
        let path = path("identity-tamper");
        cleanup(&path);
        let (memory, id, payloads) = signing_support::rc1_review_with("identity");
        let mut authority =
            DurableFixturePromotionAuthority::create_from_in_memory(&path, binding(), &memory)
                .unwrap();
        let [stage, _, _] = verified_stage_support::verified_stages(&payloads);
        stage
            .commit(&mut authority, &id, 2, CommandId::fixture("qualify"))
            .unwrap();
        drop(authority);
        replace_after(&path, "\"rc1\":", needle, replacement);
        assert!(
            DurableFixturePromotionAuthority::reopen(&path, binding()).is_err(),
            "case {index}"
        );
        cleanup(&path);
    }
}
