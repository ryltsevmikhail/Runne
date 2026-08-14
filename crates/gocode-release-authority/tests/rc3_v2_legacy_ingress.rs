#![cfg(feature = "fixture-only")]

use gocode_release_authority::{
    AuthorityError, CommandId, Digest, DurableFixturePromotionAuthority,
    ThresholdFixtureStoreBinding,
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

#[test]
fn durable_legacy_rc3_ingress_is_superseded_without_file_mutation() {
    let path =
        std::path::Path::new("/dev/shm").join(format!("gocode-rc3-v2-{}", std::process::id()));
    cleanup(&path);
    let (memory, promotion, payloads) = signing_support::qualified_unsigned_with("legacy-ingress");
    let mut store =
        DurableFixturePromotionAuthority::create_from_in_memory(&path, binding(), &memory).unwrap();
    let before = std::fs::read(&path).unwrap();
    let [_, _, stage] = verified_stage_support::verified_stages(&payloads);
    assert_eq!(
        stage.raw().commit(
            &mut store,
            &promotion,
            3,
            CommandId::fixture("legacy"),
            gocode_release_authority::CanonicalPayloadKind::Rc3Authorization
        ),
        Err(AuthorityError::AuthorityVersionSuperseded)
    );
    drop(store);
    assert_eq!(std::fs::read(&path).unwrap(), before);
    cleanup(&path);
}

fn binding() -> ThresholdFixtureStoreBinding {
    ThresholdFixtureStoreBinding::new(
        Digest::fixture(verified_stage_support::bootstrap_digest()),
        "fixture-v1",
        1,
    )
    .unwrap()
}

fn cleanup(path: &std::path::Path) {
    let _ = std::fs::remove_file(path);
    let _ = std::fs::remove_file(path.with_extension("lease"));
}
