#[test]
fn missing_or_corrupt_singleton_state_is_rejected_on_open() {
    for sql in [
        "DELETE FROM runne_session_binding_state;",
        "PRAGMA ignore_check_constraints = ON; UPDATE runne_session_binding_state SET last_created_at = -1;",
    ] {
        let path = db_path();
        drop(SqliteSessionBindingStore::open(&path).unwrap());
        raw(&path).execute_batch(sql).unwrap();
        assert!(matches!(
            SqliteSessionBindingStore::open(&path),
            Err(BindingError::StorageFailure)
        ));
    }
}

#[test]
fn namespaced_metadata_coexists_with_store_schema_version() {
    let path = db_path();
    let conn = raw(&path);
    conn.execute_batch("CREATE TABLE schema_version (version INTEGER PRIMARY KEY); INSERT INTO schema_version VALUES (99);").unwrap();
    drop(conn);
    let store = SqliteSessionBindingStore::open(&path).unwrap();
    assert_eq!(
        store.ensure_pending(&key(), &context()),
        Ok(EnsurePendingResult::Created)
    );
    assert_eq!(
        raw(&path)
            .query_row("SELECT version FROM schema_version", [], |row| row
                .get::<_, i64>(0))
            .unwrap(),
        99
    );
}

#[test]
fn pagination_is_complete_ordered_and_authority_isolated() {
    let path = db_path();
    let store = SqliteSessionBindingStore::open_with_clock(
        &path,
        Arc::new(FixedClock(Ok(NonNegativeUnixMillis::new(1).unwrap()))),
    )
    .unwrap();
    let authority = key().runtime_authority_id;
    for n in [5, 4, 3, 2, 1] {
        let key = another_key(n);
        store
            .ensure_pending(&key, &another_context(n + 10))
            .unwrap();
    }
    let mut all = Vec::new();
    let mut after = None;
    loop {
        let page = store.list_pending(&authority, 2, after.as_ref()).unwrap();
        if page.is_empty() {
            break;
        }
        after = page.last().cloned();
        all.extend(page);
    }
    assert_eq!(all.len(), 5);
    assert!(all.windows(2).all(|pair| pair[0].0 < pair[1].0));
    let other = BindingRuntimeAuthorityId::new("authority-b").unwrap();
    assert_eq!(store.list_pending(&other, 2, None), Ok(Vec::new()));
}

#[test]
fn pagination_uses_full_keyset_tiebreak_when_created_at_is_equal() {
    let path = db_path();
    let store = SqliteSessionBindingStore::open_with_clock(
        &path,
        Arc::new(FixedClock(Ok(NonNegativeUnixMillis::new(1).unwrap()))),
    )
    .unwrap();
    let authority = key().runtime_authority_id;
    let mut expected = Vec::new();
    for n in [5, 4, 3, 2, 1] {
        let key = another_key(n);
        store
            .ensure_pending(&key, &another_context(n + 10))
            .unwrap();
        expected.push(key);
    }
    raw(&path)
        .execute("UPDATE session_bindings SET created_at = 42", [])
        .unwrap();
    raw(&path)
        .execute(
            "UPDATE runne_session_binding_state SET last_created_at = 42 WHERE singleton = 1",
            [],
        )
        .unwrap();
    expected.sort_by(|left, right| {
        (
            left.session_id.as_str(),
            left.profile_id.as_str(),
            left.profile_revision,
            left.runtime_authority_id.as_str(),
        )
            .cmp(&(
                right.session_id.as_str(),
                right.profile_id.as_str(),
                right.profile_revision,
                right.runtime_authority_id.as_str(),
            ))
    });
    let mut actual = Vec::new();
    let mut after = None;
    loop {
        let page = store.list_pending(&authority, 2, after.as_ref()).unwrap();
        if page.is_empty() {
            break;
        }
        after = page.last().cloned();
        actual.extend(page.into_iter().map(|(_, key)| key));
    }
    assert_eq!(actual, expected);
    assert_eq!(actual.len(), 5);
}

#[test]
fn pagination_rejects_invalid_limits_and_invalid_cursors() {
    let path = db_path();
    let store = SqliteSessionBindingStore::open(&path).unwrap();
    let key = key();
    store.ensure_pending(&key, &context()).unwrap();
    assert!(matches!(
        store.list_pending(&key.runtime_authority_id, 0, None),
        Err(BindingError::InvalidLimit { .. })
    ));
    assert!(matches!(
        store.list_pending(&key.runtime_authority_id, 1_001, None),
        Err(BindingError::InvalidLimit { .. })
    ));
    assert_eq!(
        store
            .list_pending(&key.runtime_authority_id, 1_000, None)
            .unwrap()
            .len(),
        1
    );
    let fake = (NonNegativeUnixMillis::new(0).unwrap(), key.clone());
    assert_eq!(
        store.list_pending(&key.runtime_authority_id, 1, Some(&fake)),
        Err(BindingError::Conflict(key.clone()))
    );
    let wrong = BindingRuntimeAuthorityId::new("other").unwrap();
    assert_eq!(
        store.list_pending(
            &wrong,
            1,
            Some(&(NonNegativeUnixMillis::new(1).unwrap(), key.clone()))
        ),
        Err(BindingError::Conflict(key))
    );
}

#[cfg(unix)]
#[test]
fn reopening_hardens_database_and_existing_sidecars_to_owner_only() {
    use std::os::unix::fs::PermissionsExt;
    let path = db_path();
    let store = SqliteSessionBindingStore::open(&path).unwrap();
    store.ensure_pending(&key(), &context()).unwrap();
    let sidecars = [
        &path,
        &std::path::PathBuf::from(format!("{}-wal", path.display())),
        &std::path::PathBuf::from(format!("{}-shm", path.display())),
    ];
    for candidate in sidecars {
        assert!(
            candidate.exists(),
            "{} must exist while connection is active",
            candidate.display()
        );
        assert_eq!(
            std::fs::metadata(candidate).unwrap().permissions().mode() & 0o077,
            0,
            "{}",
            candidate.display()
        );
        std::fs::set_permissions(candidate, std::fs::Permissions::from_mode(0o644)).unwrap();
    }
    store
        .ensure_pending(&another_key(8), &another_context(18))
        .unwrap();
    for candidate in sidecars {
        assert!(candidate.exists());
        assert_eq!(
            std::fs::metadata(candidate).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
    drop(store);
    let reopened = SqliteSessionBindingStore::open(&path).unwrap();
    for candidate in sidecars {
        if candidate.exists() {
            assert_eq!(
                std::fs::metadata(candidate).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
    }
    drop(reopened);
}

#[test]
fn file_uri_is_rejected_before_sqlite_open() {
    assert!(matches!(
        SqliteSessionBindingStore::open("file:binding-test?mode=memory"),
        Err(BindingError::StorageFailure)
    ));
}

#[test]
fn stale_allocator_state_is_rejected_on_reopen() {
    let path = db_path();
    let store = SqliteSessionBindingStore::open_with_clock(
        &path,
        Arc::new(FixedClock(Ok(NonNegativeUnixMillis::new(9).unwrap()))),
    )
    .unwrap();
    store.ensure_pending(&key(), &context()).unwrap();
    drop(store);
    raw(&path)
        .execute(
            "UPDATE runne_session_binding_state SET last_created_at = 0",
            [],
        )
        .unwrap();
    assert!(matches!(
        SqliteSessionBindingStore::open(&path),
        Err(BindingError::StorageFailure)
    ));
}
