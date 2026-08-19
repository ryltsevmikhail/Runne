use runne_local_store::{
    LocalStore, ReplayApplyOutcome, ReplayScopeKey, ReplayStoreError, ReplayTransition,
};
use runne_secure_store::test_support::DeterministicSecureStore;
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

#[test]
fn anchored_replay_rejects_every_persisted_replay_field_tamper() {
    let updates = [
        ("event_journal", "runtime_authority='x'"),
        ("event_journal", "principal='x'"),
        ("event_journal", "lineage='x'"),
        ("event_journal", "scope='x'"),
        (
            "event_journal",
            "binding_digest='2222222222222222222222222222222222222222222222222222222222222222'",
        ),
        ("event_journal", "event_id='x'"),
        ("event_journal", "cursor='x'"),
        ("event_journal", "generation=2"),
        ("event_journal", "event_sequence=2"),
        ("event_journal", "validated_event=x'78'"),
        (
            "event_journal",
            "event_digest='2222222222222222222222222222222222222222222222222222222222222222'",
        ),
        ("event_journal", "projection_revision=2"),
        (
            "event_journal",
            "projection_digest='2222222222222222222222222222222222222222222222222222222222222222'",
        ),
        ("event_journal", "projected_payload=x'7b7d'"),
        ("projections", "runtime_authority='x'"),
        ("projections", "principal='x'"),
        ("projections", "lineage='x'"),
        ("projections", "scope='x'"),
        (
            "projections",
            "binding_digest='2222222222222222222222222222222222222222222222222222222222222222'",
        ),
        ("projections", "projection_revision=2"),
        (
            "projections",
            "projection_digest='2222222222222222222222222222222222222222222222222222222222222222'",
        ),
        ("projections", "event_sequence=2"),
        ("projections", "payload=x'7b7d'"),
        ("replay_cursors", "runtime_authority='x'"),
        ("replay_cursors", "principal='x'"),
        ("replay_cursors", "lineage='x'"),
        ("replay_cursors", "scope='x'"),
        (
            "replay_cursors",
            "binding_digest='2222222222222222222222222222222222222222222222222222222222222222'",
        ),
        ("replay_cursors", "generation=2"),
        ("replay_cursors", "applied_cursor='x'"),
        ("replay_cursors", "event_sequence=2"),
        ("replay_cursors", "projection_revision=2"),
        (
            "replay_cursors",
            "projection_digest='2222222222222222222222222222222222222222222222222222222222222222'",
        ),
    ];
    for (index, (table, update)) in updates.into_iter().enumerate() {
        let directory = tempfile::tempdir().expect("temporary profile");
        let profile = [80 + u8::try_from(index).expect("profile index"); 32];
        let secure = DeterministicSecureStore::new(profile);
        let path = directory.path().join("profile.sqlite3");
        let mut store = LocalStore::open_anchored(&path, &secure, profile).expect("admitted");
        let scope = scope();
        store
            .apply_anchored_replay_transition(&secure, &transition(&scope))
            .expect("apply");
        drop(store);
        rusqlite::Connection::open(&path)
            .expect("database")
            .execute(&format!("UPDATE {table} SET {update}"), [])
            .expect("tamper");
        assert!(
            LocalStore::open_anchored(&path, &secure, profile).is_err(),
            "{table}: {update}"
        );
    }
}

#[test]
fn anchored_replay_rejects_tamper_before_an_unchanged_duplicate() {
    let directory = tempfile::tempdir().expect("temporary profile");
    let profile = [42; 32];
    let secure = DeterministicSecureStore::new(profile);
    let path = directory.path().join("profile.sqlite3");
    let mut store = LocalStore::open_anchored(&path, &secure, profile).expect("admitted");
    let scope = scope();
    let event = transition(&scope);
    store
        .apply_anchored_replay_transition(&secure, &event)
        .expect("apply");
    rusqlite::Connection::open(&path)
        .expect("database")
        .execute("UPDATE event_journal SET cursor='forged'", [])
        .expect("tamper");
    assert!(
        store
            .apply_anchored_replay_transition(&secure, &event)
            .is_err()
    );
}

#[test]
fn anchored_replay_rejects_tamper_before_a_changed_transition() {
    let directory = tempfile::tempdir().expect("temporary profile");
    let profile = [43; 32];
    let secure = DeterministicSecureStore::new(profile);
    let path = directory.path().join("profile.sqlite3");
    let mut store = LocalStore::open_anchored(&path, &secure, profile).expect("admitted");
    let scope = scope();
    let first = transition(&scope);
    store
        .apply_anchored_replay_transition(&secure, &first)
        .expect("apply");
    rusqlite::Connection::open(&path)
        .expect("database")
        .execute("UPDATE projections SET payload=x'7b7d'", [])
        .expect("tamper");
    let event_bytes = br#"{"event":2}"#;
    let projection_bytes = br#"{"messages":[2]}"#;
    let checkpoint = runne_local_store::ReplayCheckpoint {
        cursor: "cursor-1".into(),
        generation: 1,
        event_sequence: 1,
        projection_revision: 1,
        projection_digest: digest(br#"{"messages":[]}"#),
        binding_digest: scope.binding_digest.clone(),
    };
    let changed = ReplayTransition {
        scope: &scope,
        expected_checkpoint: Some(&checkpoint),
        event_id: "event-2",
        cursor: "cursor-2",
        generation: 2,
        event_sequence: 2,
        event_bytes,
        event_digest: digest(event_bytes),
        projection_revision: 2,
        projection_bytes,
        projection_digest: digest(projection_bytes),
    };
    assert!(
        store
            .apply_anchored_replay_transition(&secure, &changed)
            .is_err()
    );
}
