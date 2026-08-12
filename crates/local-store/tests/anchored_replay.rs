use gocode_local_store::{
    LocalStore, ReplayApplyOutcome, ReplayScopeKey, ReplayStoreError, ReplayTransition,
};
use gocode_secure_store::test_support::DeterministicSecureStore;
use sha2::{Digest, Sha256};

fn digest(value: &[u8]) -> String {
    format!("{:x}", Sha256::digest(value))
}

fn scope() -> ReplayScopeKey {
    ReplayScopeKey {
        runtime_authority: "runtime".into(),
        principal: "principal".into(),
        lineage: "lineage".into(),
        scope: "conversation".into(),
        binding_digest: digest(b"binding"),
    }
}

fn transition(scope: &ReplayScopeKey) -> ReplayTransition<'_> {
    let event = b"event";
    let projection = br#"{"messages":[]}"#;
    ReplayTransition {
        scope,
        expected_checkpoint: None,
        event_id: "event-1",
        cursor: "cursor-1",
        generation: 1,
        event_sequence: 1,
        event_bytes: event,
        event_digest: digest(event),
        projection_revision: 1,
        projection_bytes: projection,
        projection_digest: digest(projection),
    }
}

#[test]
fn anchored_replay_advances_once_and_fences_offline_writers() {
    let directory = tempfile::tempdir().expect("temporary profile");
    let profile = [31; 32];
    let secure = DeterministicSecureStore::new(profile);
    let path = directory.path().join("profile.sqlite3");
    let mut store = LocalStore::open_anchored(&path, &secure, profile).expect("admitted");
    let scope = scope();
    let event = transition(&scope);
    assert!(matches!(
        store.apply_replay_transition(&event),
        Err(ReplayStoreError::AnchoredAdmissionRequired)
    ));
    assert_eq!(
        store
            .apply_anchored_replay_transition(&secure, &event)
            .expect("anchored apply"),
        ReplayApplyOutcome::Applied {
            database_generation: 2
        }
    );
    assert_eq!(
        store
            .apply_anchored_replay_transition(&secure, &event)
            .expect("duplicate"),
        ReplayApplyOutcome::AlreadyApplied {
            database_generation: 2
        }
    );
    assert!(
        store
            .reset_anchored_replay_scope(&secure, &scope)
            .expect("anchored reset")
    );
    assert!(
        !store
            .reset_anchored_replay_scope(&secure, &scope)
            .expect("empty reset")
    );
}
