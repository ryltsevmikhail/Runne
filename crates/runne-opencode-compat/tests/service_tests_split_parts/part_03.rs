impl SessionBindingStore for ImpossibleCommittedStore {
    fn ensure_pending(
        &self,
        _key: &SessionBindingKey,
        _context: &SessionBindingContext,
    ) -> Result<EnsurePendingResult, BindingError> {
        Ok(EnsurePendingResult::AlreadyCommitted)
    }

    fn commit(
        &self,
        key: &SessionBindingKey,
        _expected_conversation_id: ConversationId,
        _response: &runne_api::OpenCodeSessionInfo,
    ) -> Result<(), BindingError> {
        Err(BindingError::NotFound(key.clone()))
    }

    fn lookup(
        &self,
        _key: &SessionBindingKey,
    ) -> Result<Option<SessionBindingStatus>, BindingError> {
        Ok(None)
    }

    fn list_pending(
        &self,
        _authority: &BindingRuntimeAuthorityId,
        _limit: usize,
        _after: Option<&(NonNegativeUnixMillis, SessionBindingKey)>,
    ) -> Result<Vec<(NonNegativeUnixMillis, SessionBindingKey)>, BindingError> {
        Ok(Vec::new())
    }
}

#[tokio::test]
async fn impossible_committed_state_fails_closed_before_host() {
    let host = MockHost::succeeds();
    let sut = OpenCodeSessionCreateService::new(
        ImpossibleCommittedStore,
        host.clone(),
        ProfileRef {
            profile_id: ProfileId::new("opencode-baseline-inventory").expect("profile"),
            profile_revision: 2,
        },
        schema(),
    );
    let error = sut
        .create_session(key(), &request(), input())
        .await
        .unwrap_err();

    assert!(matches!(
        error,
        SessionCreateError::ImpossibleCommittedBinding { .. }
    ));
    assert_eq!(host.calls(), 0);
}

#[test]
fn fingerprint_is_deterministic_and_unambiguous() {
    let first = input();
    let mut changed = input();
    changed.workspace_id = Some("wire-workspace-2".into());

    assert_eq!(fingerprint(&first), fingerprint(&first));
    assert_ne!(fingerprint(&first), fingerprint(&changed));
}

#[test]
fn pending_listing_requires_a_nonzero_bounded_limit() {
    let binding = MockBindingStore::default();
    let host = MockHost::succeeds();
    let sut = service(binding.clone(), host);
    let authority = BindingRuntimeAuthorityId::new("runtime-a").unwrap();

    assert!(matches!(
        sut.list_pending_for_recovery(&authority, 0, None),
        Err(RecoveryListError::InvalidLimit { actual: 0, .. })
    ));
    assert!(matches!(
        sut.list_pending_for_recovery(&authority, 1_001, None),
        Err(RecoveryListError::InvalidLimit { actual: 1_001, .. })
    ));
    assert!(sut.list_pending_for_recovery(&authority, 1, None).is_ok());
    assert_eq!(binding.list_calls.lock().unwrap().len(), 1);
}
