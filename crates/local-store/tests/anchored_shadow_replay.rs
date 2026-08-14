#![cfg(feature = "test-support")]

use gocode_local_store::{
    LocalStore, ReplayApplyOutcome, ReplayScopeKey, ReplayStoreError, ReplayTransition,
};
use gocode_secure_store::test_support::DeterministicSecureStore;
use sha2::{Digest, Sha256};

fn digest(value: &[u8]) -> String {
    format!("{:x}", Sha256::digest(value))
}

fn scope(kind: &str) -> ReplayScopeKey {
    ReplayScopeKey {
        runtime_authority: "runtime".into(),
        principal: "principal".into(),
        lineage: "lineage".into(),
        scope: kind.into(),
        binding_digest: digest(b"binding"),
    }
}

#[test]
fn anchored_shadow_begin_is_opaque_and_does_not_replace_active_projection() {
    let directory = tempfile::tempdir().expect("temporary profile");
    let profile = [89; 32];
    let secure = DeterministicSecureStore::new(profile);
    let path = directory.path().join("profile.sqlite3");
    let mut store = LocalStore::open_anchored(&path, &secure, profile).expect("admitted");
    let seed = gocode_local_store::ReplayBaselineSeed::for_local_store_test(
        &scope("conversation"),
        "session",
        "codec-v1",
        br#"{"messages":[]}"#,
        7,
        3,
        4_102_444_800_000,
    )
    .expect("bounded test seed");

    let shadow = store
        .begin_anchored_shadow_replay(&secure, &scope("conversation"), &seed)
        .expect("shadow persisted");

    assert!(shadow.as_str().starts_with("shadow-"));
    assert_eq!(
        store
            .authenticated_conversation_projection(&secure, &scope("conversation"))
            .expect("read active"),
        None
    );
}

#[test]
fn promoted_shadow_becomes_the_only_visible_projection_after_second_anchor() {
    let directory = tempfile::tempdir().expect("temporary profile");
    let profile = [90; 32];
    let secure = DeterministicSecureStore::new(profile);
    let path = directory.path().join("profile.sqlite3");
    let mut store = LocalStore::open_anchored(&path, &secure, profile).expect("admitted");
    let replay_scope = scope("task-run");
    let seed = gocode_local_store::ReplayBaselineSeed::for_local_store_test(
        &replay_scope,
        "session",
        "codec-v1",
        br#"{"steps":[]}"#,
        8,
        4,
        4_102_444_800_000,
    )
    .expect("bounded test seed");
    let shadow = store
        .begin_anchored_shadow_replay(&secure, &replay_scope, &seed)
        .expect("shadow persisted");
    let accepted = gocode_local_store::ShadowResumeAcceptance::for_local_store_test(
        &seed,
        "baseline-cursor",
        4,
        0,
        br#"{"steps":[]}"#,
    )
    .expect("accepted baseline");
    store
        .accept_anchored_shadow_resume(&secure, &replay_scope, &shadow, &accepted)
        .expect("persist accepted baseline");
    store
        .seal_anchored_shadow_promotion(&secure, &replay_scope, &shadow, None)
        .expect("pending promotion sealed");

    let committed = store
        .commit_anchored_shadow_promotion(&secure, &replay_scope, &shadow)
        .expect("promoted after anchor readback");
    let duplicate = store
        .commit_anchored_shadow_promotion(&secure, &replay_scope, &shadow)
        .expect("exact duplicate is idempotent");

    assert_eq!(
        committed.value.projection_digest,
        digest(br#"{"steps":[]}"#)
    );
    assert_eq!(duplicate.value, committed.value);
    assert_eq!(
        store
            .authenticated_conversation_projection(&secure, &replay_scope)
            .expect("read promoted"),
        Some(gocode_local_store::StoredConversationProjection {
            payload: br#"{"steps":[]}"#.to_vec(),
            revision: 0,
            digest: digest(br#"{"steps":[]}"#),
            event_sequence: 8,
            binding_digest: replay_scope.binding_digest,
        })
    );
}

#[test]
fn expired_shadow_baseline_is_rejected_before_any_anchored_write() {
    let directory = tempfile::tempdir().expect("temporary profile");
    let profile = [91; 32];
    let secure = DeterministicSecureStore::new(profile);
    let path = directory.path().join("profile.sqlite3");
    let mut store = LocalStore::open_anchored(&path, &secure, profile).expect("admitted");
    let expired = gocode_local_store::ReplayBaselineSeed::for_local_store_test(
        &scope("conversation"),
        "session",
        "codec-v1",
        br#"{"messages":[]}"#,
        7,
        3,
        1,
    )
    .expect("bounded test seed");

    assert!(
        store
            .begin_anchored_shadow_replay(&secure, &scope("conversation"), &expired)
            .is_err()
    );
    assert_eq!(
        store
            .authenticated_conversation_projection(&secure, &scope("conversation"))
            .expect("active state unchanged"),
        None
    );
}

#[test]
fn shadow_without_an_exact_suffix_checkpoint_cannot_be_promoted() {
    let directory = tempfile::tempdir().expect("temporary profile");
    let profile = [92; 32];
    let secure = DeterministicSecureStore::new(profile);
    let path = directory.path().join("profile.sqlite3");
    let mut store = LocalStore::open_anchored(&path, &secure, profile).expect("admitted");
    let replay_scope = scope("conversation");
    let seed = gocode_local_store::ReplayBaselineSeed::for_local_store_test(
        &replay_scope,
        "session",
        "codec-v1",
        br#"{"messages":[]}"#,
        8,
        4,
        4_102_444_800_000,
    )
    .expect("bounded test seed");
    let shadow = store
        .begin_anchored_shadow_replay(&secure, &replay_scope, &seed)
        .expect("shadow persisted");

    assert!(
        store
            .seal_anchored_shadow_promotion(&secure, &replay_scope, &shadow, None)
            .is_err()
    );
    assert_eq!(
        store
            .authenticated_conversation_projection(&secure, &replay_scope)
            .expect("old active remains visible"),
        None
    );
}

#[path = "anchored_shadow_replay/promoted.rs"]
mod promoted;
