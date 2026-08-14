use super::super::*;
use gocode_secure_store::{SecureStore, StoredSecurityAnchor};
use std::{sync::Arc, time::Duration};

fn stored_anchor(secure: &DeterministicSecureStore, profile: [u8; 32]) -> StoredSecurityAnchor {
    let lock = secure
        .acquire_security_profile_lock(profile)
        .expect("profile lock");
    secure.read_security_anchor(&lock).expect("anchor")
}

#[test]
fn noncanonical_trigger_is_rejected_without_anchor_advance() {
    let directory = tempfile::tempdir().expect("temporary profile");
    let profile = [121; 32];
    let secure = DeterministicSecureStore::new(profile);
    let path = directory.path().join("profile.sqlite3");
    drop(LocalStore::open_anchored(&path, &secure, profile).expect("admitted"));
    let before = stored_anchor(&secure, profile);
    Connection::open(&path)
        .expect("offline database")
        .execute_batch(
            "CREATE TRIGGER restore_pending AFTER DELETE ON replay_promotion_pending BEGIN UPDATE replay_active_generations SET selector=OLD.old_selector,shadow_id=OLD.old_shadow_id WHERE runtime_authority=OLD.runtime_authority AND principal=OLD.principal AND lineage=OLD.lineage AND scope=OLD.scope; END;",
        )
        .expect("install trigger");

    assert!(LocalStore::open_anchored(&path, &secure, profile).is_err());
    assert_eq!(stored_anchor(&secure, profile), before);
}

#[test]
fn reset_refuses_unselected_or_pending_shadow_state() {
    for seal_pending in [false, true] {
        let directory = tempfile::tempdir().expect("temporary profile");
        let profile = if seal_pending { [122; 32] } else { [123; 32] };
        let secure = DeterministicSecureStore::new(profile);
        let path = directory.path().join("profile.sqlite3");
        let mut store = LocalStore::open_anchored(&path, &secure, profile).expect("admitted");
        let replay_scope = scope();
        let seed = gocode_local_store::ReplayBaselineSeed::for_local_store_test(
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
            "baseline-cursor",
            4,
            0,
            br#"{"messages":[]}"#,
        )
        .expect("acceptance");
        store
            .accept_anchored_shadow_resume(&secure, &replay_scope, &shadow, &accepted)
            .expect("accepted");
        if seal_pending {
            store
                .seal_anchored_shadow_promotion(&secure, &replay_scope, &shadow, None)
                .expect("pending");
        }

        assert!(matches!(
            store.reset_anchored_replay_scope(&secure, &replay_scope),
            Err(ReplayStoreError::PromotionConflict)
        ));
    }
}

#[test]
fn baseline_expiring_while_waiting_for_profile_lock_writes_nothing() {
    let directory = tempfile::tempdir().expect("temporary profile");
    let profile = [124; 32];
    let secure = Arc::new(DeterministicSecureStore::new(profile));
    let path = directory.path().join("profile.sqlite3");
    let mut store = LocalStore::open_anchored(&path, secure.as_ref(), profile).expect("admitted");
    let replay_scope = scope();
    let expiry = u64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_millis(),
    )
    .expect("millisecond clock")
        + 100;
    let seed = gocode_local_store::ReplayBaselineSeed::for_local_store_test(
        &replay_scope,
        "session",
        "codec-v1",
        br#"{"messages":[]}"#,
        8,
        4,
        expiry,
    )
    .expect("seed");
    let before = stored_anchor(secure.as_ref(), profile);
    let (ready_tx, ready_rx) = std::sync::mpsc::sync_channel(0);
    let holder = Arc::clone(&secure);
    let releaser = std::thread::spawn(move || {
        let held = holder
            .acquire_security_profile_lock(profile)
            .expect("held profile lock");
        ready_tx.send(()).expect("lock ready");
        std::thread::sleep(Duration::from_millis(250));
        drop(held);
    });
    ready_rx.recv().expect("lock acquired");
    let result = store.begin_anchored_shadow_replay(secure.as_ref(), &replay_scope, &seed);
    releaser.join().expect("release lock");
    assert!(matches!(result, Err(ReplayStoreError::InvalidBaseline)));
    assert_eq!(stored_anchor(secure.as_ref(), profile), before);
}

fn seed_legacy_replay(
    store: &mut LocalStore,
    secure: &DeterministicSecureStore,
    replay_scope: &ReplayScopeKey,
) {
    let event = br#"{"kind":"legacy"}"#;
    let projection = br#"{"messages":[]}"#;
    store
        .apply_anchored_replay_transition(
            secure,
            &ReplayTransition {
                scope: replay_scope,
                expected_checkpoint: None,
                event_id: "legacy-event",
                cursor: "legacy-cursor",
                generation: 1,
                event_sequence: 1,
                event_bytes: event,
                event_digest: format!("{:x}", Sha256::digest(event)),
                projection_revision: 1,
                projection_bytes: projection,
                projection_digest: format!("{:x}", Sha256::digest(projection)),
            },
        )
        .expect("legacy replay");
}

#[test]
fn v7_migration_rejects_sealed_inconsistent_replay_without_advancing() {
    let directory = tempfile::tempdir().expect("temporary profile");
    let profile = [125; 32];
    let secure = DeterministicSecureStore::new(profile);
    let path = directory.path().join("profile.sqlite3");
    let mut store = LocalStore::open_anchored(&path, &secure, profile).expect("admitted");
    seed_legacy_replay(&mut store, &secure, &scope());
    gocode_local_store::security_open_test_support::downgrade_to_v7_for_test(
        &mut store,
        &secure,
        "UPDATE projections SET projection_digest=replace(lower(hex(zeroblob(32))),'0','a')",
    )
    .expect("sealed V7 fixture");
    drop(store);
    let before = stored_anchor(&secure, profile);

    assert!(LocalStore::open_anchored(&path, &secure, profile).is_err());
    assert_eq!(stored_anchor(&secure, profile), before);
    assert_eq!(
        Connection::open(&path)
            .unwrap()
            .pragma_query_value(None, "user_version", |row| row.get::<_, i64>(0))
            .unwrap(),
        7
    );
}

#[test]
fn populated_v7_migration_recovers_cas_and_readback_windows() {
    for readback_loss in [false, true] {
        let directory = tempfile::tempdir().expect("temporary profile");
        let profile = if readback_loss { [126; 32] } else { [127; 32] };
        let secure = DeterministicSecureStore::new(profile);
        let path = directory.path().join("profile.sqlite3");
        let mut store = LocalStore::open_anchored(&path, &secure, profile).expect("admitted");
        let replay_scope = scope();
        seed_legacy_replay(&mut store, &secure, &replay_scope);
        gocode_local_store::security_open_test_support::downgrade_to_v7_for_test(
            &mut store, &secure, "",
        )
        .expect("sealed V7 fixture");
        drop(store);
        if readback_loss {
            secure.fail_read_after(1);
        } else {
            secure.fail_next_advance();
        }
        assert!(LocalStore::open_anchored(&path, &secure, profile).is_err());
        let mut reopened = LocalStore::open_anchored(&path, &secure, profile).expect("recover V8");
        assert_eq!(
            reopened
                .authenticated_replay_checkpoint(&secure, &replay_scope)
                .unwrap()
                .unwrap()
                .event_sequence,
            1
        );
    }
}

#[test]
fn v7_migration_reauthenticates_source_inside_the_write_transaction() {
    for tamper_in_window in [false, true] {
        let directory = tempfile::tempdir().expect("temporary profile");
        let profile = if tamper_in_window {
            [128; 32]
        } else {
            [129; 32]
        };
        let secure = DeterministicSecureStore::new(profile);
        let path = directory.path().join("profile.sqlite3");
        let mut store = LocalStore::open_anchored(&path, &secure, profile).expect("admitted");
        seed_legacy_replay(&mut store, &secure, &scope());
        gocode_local_store::security_open_test_support::downgrade_to_v7_for_test(
            &mut store, &secure, "",
        )
        .expect("sealed V7 fixture");
        drop(store);
        let before = stored_anchor(&secure, profile);
        let mutation_path = path.clone();
        gocode_local_store::security_open_test_support::install_admitted_open_hooks(
            move || {
                if tamper_in_window {
                    Connection::open(&mutation_path)
                        .unwrap()
                        .execute(
                            "UPDATE event_journal SET event_id='window-tampered-event'",
                            [],
                        )
                        .unwrap();
                }
            },
            || {},
        );

        let opened = LocalStore::open_anchored(&path, &secure, profile);
        if tamper_in_window {
            assert!(opened.is_err());
            assert_eq!(stored_anchor(&secure, profile), before);
            assert_eq!(
                Connection::open(&path)
                    .unwrap()
                    .pragma_query_value(None, "user_version", |row| row.get::<_, i64>(0))
                    .unwrap(),
                7
            );
        } else {
            assert!(opened.is_ok());
        }
    }
}
