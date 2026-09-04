use super::*;

#[test]
fn same_generation_authority_renewal_fences_old_stream_publication() {
    for approval in [false, true] {
        let directory = tempfile::tempdir().unwrap();
        secure_directory(directory.path());
        let path = managed_path(directory.path(), "authority-renewal.sqlite");
        let lifecycle = open_test_store(&path, 100);
        complete_pair(&lifecycle, 84, "authority-renewal");
        drop(lifecycle);
        let store = SqliteProviderExecutionStore::open_with_now(&path, Arc::new(|| 100)).unwrap();
        let launch = store.activate_runtime_launch(&config()).unwrap();
        super::super::super::online_proof_test_support::arm(&store);
        let admission = match store
            .issue(
                &launch,
                &super::super::super::authority_test_support::prepare_request_for_provider(
                    &launch, &path, 84, "openai",
                ),
            )
            .unwrap()
        {
            ProviderAuthorityIssueOutcome::Winner(value) => value,
            _ => panic!("fresh admission"),
        };
        let lifecycle = reopen_test_store(&path, 100);
        let (_, binding) = lifecycle
            .authorize_online_dispatch(&launch, admission.claim(), 100)
            .unwrap()
            .split();
        store
            .start_online_effect(&launch, admission.claim(), &binding)
            .unwrap();
        let dispatch = crate::provider::SqliteProviderDispatchStore::open_with_connection(
            path.to_str().unwrap(),
            super::super::super::authority_test_support::configured_connection(&path),
        )
        .unwrap();
        let mut renewed = config();
        if approval {
            renewed.approval_revision += 1;
        } else {
            renewed.capability_revision += 1;
        }
        store.install_runtime_authority(&renewed).unwrap();
        assert_eq!(
            dispatch.mark_streaming_online(
                &crate::provider::MarkProviderStreaming {
                    attempt_id: admission.claim().attempt_id,
                    fencing_token: admission.claim().fencing_token,
                    stream_id: runne_provider::ProviderStreamId::from_bytes([85; 16]),
                },
                || 100
            ),
            Err(crate::provider::ProviderStoreError::StaleFencingToken)
        );
        assert_eq!(
            dispatch
                .get_dispatch(admission.claim().attempt_id)
                .unwrap()
                .unwrap()
                .state,
            crate::provider::ProviderDispatchState::Dispatching
        );
    }
}
