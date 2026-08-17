use rusqlite::Connection;

use super::*;

#[test]
fn expired_active_pending_command_completes_before_gc_and_uses_next_version() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("expired-active-pending.sqlite");
    let (lifecycle, _) = CredentialAuthorityPair::new().split();
    let store =
        SqliteProviderCredentialLifecycleStore::open_at_with_authority(&path, lifecycle, 100)
            .unwrap();
    let provider = ProviderId::new("openai").unwrap();
    let source = store.provision_source([0x71; 16]).unwrap();
    let provision = store
        .begin_provision(&provider, [0x72; 16], &source)
        .unwrap();
    let provision = store.mark_native_created(&provision).unwrap();
    store
        .activate(
            CredentialLease::new(provision.version_ref().clone(), [0x73; 16], 101, 1).unwrap(),
        )
        .unwrap();
    drop(store);

    let connection = gocode_store::schema::open_managed_connection(
        &path,
        gocode_store::schema::ConnectionMode::Writer,
    )
    .unwrap();
    let composed = compose_credential_lifecycle(
        connection,
        [0x74; 16],
        2,
        ProviderCredentialId::OpenAi,
        true,
        Some(Arc::new(fixture_native)),
    )
    .unwrap();
    let active = composed.store.active_lease(&provider).unwrap().unwrap();
    assert_eq!(active.version_ref().version(), 2);
    assert_eq!(
        composed
            .store
            .version_state(provision.version_ref())
            .unwrap(),
        CredentialVersionState::Deleted
    );

    let states = Connection::open(&path)
        .unwrap()
        .prepare("SELECT provision_state FROM provider_credential_provisions ORDER BY credential_version")
        .unwrap()
        .query_map([], |row| row.get::<_, String>(0))
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    assert_eq!(states, ["ACTIVATED", "ACTIVATED"]);
}

#[test]
fn explicit_fixture_native_dependency_rotates_across_two_launch_generations() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("two-launch-credential.sqlite");
    let counters = Arc::new(FixtureNativeCounters::default());
    let factory: Arc<LoopbackCredentialVersionStoreFactory> = Arc::new({
        let counters = Arc::clone(&counters);
        move |authority: NativeCredentialAuthority| {
            fixture_native_with_counters(authority, Arc::clone(&counters))
        }
    });
    let provider = ProviderId::new("openai").unwrap();
    let owner = [0x84; 16];

    let connection = gocode_store::schema::open_managed_connection(
        &path,
        gocode_store::schema::ConnectionMode::Writer,
    )
    .unwrap();
    let first = compose_credential_lifecycle(
        connection,
        owner,
        1,
        ProviderCredentialId::OpenAi,
        true,
        Some(factory.clone()),
    )
    .unwrap();
    let first_ref = first
        .store
        .active_lease(&provider)
        .unwrap()
        .unwrap()
        .version_ref()
        .clone();
    drop(first);

    let connection = gocode_store::schema::open_managed_connection(
        &path,
        gocode_store::schema::ConnectionMode::Writer,
    )
    .unwrap();
    let second = compose_credential_lifecycle(
        connection,
        owner,
        2,
        ProviderCredentialId::OpenAi,
        true,
        Some(factory.clone()),
    )
    .unwrap();
    assert_eq!(
        second.store.version_state(&first_ref).unwrap(),
        CredentialVersionState::Deleted
    );
    assert_eq!(
        second
            .store
            .active_lease(&provider)
            .unwrap()
            .unwrap()
            .fencing_token(),
        2
    );
    let native = factory(second.native_authority.clone());
    reconcile_native(
        second.store.as_ref(),
        native.as_ref(),
        chrono::Utc::now().timestamp(),
    )
    .unwrap();
    assert_eq!(counters.creates.load(Ordering::SeqCst), 0);
    assert_eq!(counters.loads.load(Ordering::SeqCst), 0);
    assert_eq!(counters.deletes.load(Ordering::SeqCst), 1);
}
