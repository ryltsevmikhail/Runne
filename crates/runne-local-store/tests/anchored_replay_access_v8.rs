#![cfg(feature = "test-support")]

use runne_local_store::{
    AppliedReplayEvent, LocalStore, ReplayScopeKey, ReplayStoreError, ReplayTransition,
    SecurityStateError, ShadowResumeAcceptance,
};
use runne_secure_store::test_support::DeterministicSecureStore;
use rusqlite::Connection;
use sha2::{Digest, Sha256};

fn scope() -> ReplayScopeKey {
    ReplayScopeKey {
        runtime_authority: "runtime".into(),
        principal: "principal".into(),
        lineage: "lineage".into(),
        scope: "conversation".into(),
        binding_digest: format!("{:x}", Sha256::digest(b"binding")),
    }
}

fn promoted_shadow(
    store: &mut LocalStore,
    secure: &DeterministicSecureStore,
    scope: &ReplayScopeKey,
    expected: Option<&runne_local_store::ReplayCheckpoint>,
) -> runne_local_store::ShadowReplayId {
    let seed = runne_local_store::ReplayBaselineSeed::for_local_store_test(
        scope,
        "session",
        "codec-v1",
        br#"{"messages":[]}"#,
        8,
        4,
        4_102_444_800_000,
    )
    .expect("seed");
    let shadow = store
        .begin_anchored_shadow_replay(secure, scope, &seed)
        .expect("shadow");
    let accepted = ShadowResumeAcceptance::for_local_store_test(
        &seed,
        "baseline-cursor",
        4,
        0,
        br#"{"messages":[]}"#,
    )
    .expect("accepted baseline");
    store
        .accept_anchored_shadow_resume(secure, scope, &shadow, &accepted)
        .expect("accept baseline");
    store
        .seal_anchored_shadow_promotion(secure, scope, &shadow, expected)
        .expect("seal promotion");
    shadow
}

#[test]
fn phase_two_anchor_failure_poisoned_handle_exposes_no_replay_until_reopen() {
    for readback_loss in [false, true] {
        let directory = tempfile::tempdir().expect("temporary profile");
        let profile = if readback_loss { [115; 32] } else { [116; 32] };
        let secure = DeterministicSecureStore::new(profile);
        let path = directory.path().join("profile.sqlite3");
        let mut store = LocalStore::open_anchored(&path, &secure, profile).expect("admitted");
        let replay_scope = scope();
        let shadow = promoted_shadow(&mut store, &secure, &replay_scope, None);

        if readback_loss {
            secure.fail_read_after(1);
        } else {
            secure.fail_next_advance();
        }
        assert!(
            store
                .commit_anchored_shadow_promotion(&secure, &replay_scope, &shadow)
                .is_err()
        );
        assert!(matches!(
            store.replay_checkpoint(&replay_scope),
            Err(ReplayStoreError::AnchoredAdmissionRequired)
        ));
        assert!(matches!(
            store.conversation_projection(&replay_scope),
            Err(ReplayStoreError::AnchoredAdmissionRequired)
        ));
        assert!(matches!(
            store.authenticated_replay_checkpoint(&secure, &replay_scope),
            Err(ReplayStoreError::Security(
                SecurityStateError::AnchorAdvanceFailed
            ))
        ));
        assert!(matches!(
            store.authenticated_conversation_projection(&secure, &replay_scope),
            Err(ReplayStoreError::Security(
                SecurityStateError::AnchorAdvanceFailed
            ))
        ));
        drop(store);

        let mut reopened = LocalStore::open_anchored(&path, &secure, profile).expect("one-ahead");
        assert_eq!(
            reopened
                .authenticated_replay_checkpoint(&secure, &replay_scope)
                .expect("authenticated checkpoint")
                .expect("shadow checkpoint")
                .event_sequence,
            8
        );
        assert_eq!(
            reopened
                .authenticated_conversation_projection(&secure, &replay_scope)
                .expect("authenticated projection")
                .expect("shadow projection")
                .payload,
            br#"{"messages":[]}"#
        );
    }
}

#[test]
fn authenticated_read_rejects_tampered_orphaned_selector_and_pending_state() {
    for sql in [
        "DELETE FROM replay_active_generations",
        "UPDATE replay_active_generations SET selector='legacy',shadow_id=NULL",
        "INSERT INTO replay_promotion_pending SELECT runtime_authority,principal,lineage,scope,'legacy',NULL,replace(lower(hex(zeroblob(32))),'0','a'),shadow_id,replace(lower(hex(zeroblob(32))),'0','b') FROM replay_shadow_generations LIMIT 1; DELETE FROM replay_active_generations",
    ] {
        let directory = tempfile::tempdir().expect("temporary profile");
        let profile = [117; 32];
        let secure = DeterministicSecureStore::new(profile);
        let path = directory.path().join("profile.sqlite3");
        let mut store = LocalStore::open_anchored(&path, &secure, profile).expect("admitted");
        let replay_scope = scope();
        let shadow = promoted_shadow(&mut store, &secure, &replay_scope, None);
        store
            .commit_anchored_shadow_promotion(&secure, &replay_scope, &shadow)
            .expect("promoted");
        Connection::open(&path)
            .expect("tamper connection")
            .execute_batch(sql)
            .expect("tamper selector");
        let read = store.authenticated_replay_checkpoint(&secure, &replay_scope);
        assert!(
            matches!(read, Err(ReplayStoreError::Security(_))),
            "{read:?}"
        );
    }
}

#[test]
fn confirm_requires_authenticated_selected_generation() {
    let directory = tempfile::tempdir().expect("temporary profile");
    let profile = [118; 32];
    let secure = DeterministicSecureStore::new(profile);
    let path = directory.path().join("profile.sqlite3");
    let mut store = LocalStore::open_anchored(&path, &secure, profile).expect("admitted");
    let replay_scope = scope();
    let event = br#"{"kind":"legacy"}"#;
    let projection = br#"{"messages":["legacy"]}"#;
    let transition = ReplayTransition {
        scope: &replay_scope,
        expected_checkpoint: None,
        event_id: "same-id",
        cursor: "legacy-cursor",
        generation: 1,
        event_sequence: 1,
        event_bytes: event,
        event_digest: format!("{:x}", Sha256::digest(event)),
        projection_revision: 1,
        projection_bytes: projection,
        projection_digest: format!("{:x}", Sha256::digest(projection)),
    };
    store
        .apply_anchored_replay_transition(&secure, &transition)
        .expect("legacy event");
    let applied = AppliedReplayEvent {
        scope: &replay_scope,
        event_id: "same-id",
        cursor: "legacy-cursor",
        generation: 1,
        event_sequence: 1,
        event_bytes: event,
        event_digest: &transition.event_digest,
    };
    assert!(matches!(
        store.confirm_replay_event_applied(&applied),
        Err(ReplayStoreError::AnchoredAdmissionRequired)
    ));
    assert!(matches!(
        store
            .authenticated_confirm_replay_event_applied(&secure, &applied)
            .expect("legacy confirmation"),
        runne_local_store::ReplayApplyOutcome::AlreadyApplied { .. }
    ));
    let checkpoint = store
        .authenticated_replay_checkpoint(&secure, &replay_scope)
        .expect("checkpoint");
    let shadow = promoted_shadow(&mut store, &secure, &replay_scope, checkpoint.as_ref());
    store
        .commit_anchored_shadow_promotion(&secure, &replay_scope, &shadow)
        .expect("promoted");
    assert!(matches!(
        store.authenticated_confirm_replay_event_applied(&secure, &applied),
        Err(ReplayStoreError::EventIdentityConflict)
    ));
}

#[test]
fn phase_one_failure_and_readback_loss_recover_pending_promotion_once() {
    for readback_loss in [false, true] {
        let directory = tempfile::tempdir().expect("temporary profile");
        let profile = [119; 32];
        let secure = DeterministicSecureStore::new(profile);
        let path = directory.path().join("profile.sqlite3");
        let mut store = LocalStore::open_anchored(&path, &secure, profile).expect("admitted");
        let replay_scope = scope();
        let seed = runne_local_store::ReplayBaselineSeed::for_local_store_test(
            &replay_scope,
            "session",
            "codec-v1",
            br#"{"messages":[]}"#,
            8,
            4,
            4_102_444_800_000,
        )
        .expect("seed");
        let shadow = store
            .begin_anchored_shadow_replay(&secure, &replay_scope, &seed)
            .expect("shadow");
        let accepted = ShadowResumeAcceptance::for_local_store_test(
            &seed,
            "cursor",
            4,
            0,
            br#"{"messages":[]}"#,
        )
        .expect("accepted");
        store
            .accept_anchored_shadow_resume(&secure, &replay_scope, &shadow, &accepted)
            .expect("accept");
        if readback_loss {
            secure.fail_read_after(1);
        } else {
            secure.fail_next_advance();
        }
        assert!(
            store
                .seal_anchored_shadow_promotion(&secure, &replay_scope, &shadow, None)
                .is_err()
        );
        assert!(matches!(
            store.authenticated_replay_checkpoint(&secure, &replay_scope),
            Err(ReplayStoreError::Security(_))
        ));
        drop(store);
        let mut reopened = LocalStore::open_anchored(&path, &secure, profile).expect("recover");
        assert_eq!(
            reopened
                .authenticated_replay_checkpoint(&secure, &replay_scope)
                .expect("checkpoint")
                .expect("selected")
                .event_sequence,
            8
        );
        assert!(
            reopened
                .commit_anchored_shadow_promotion(&secure, &replay_scope, &shadow)
                .is_ok()
        );
    }
}

mod anchored_replay_access_v8 {
    mod review_regressions;
    mod shadow_confirm;
}
