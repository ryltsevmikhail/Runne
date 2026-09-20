impl ReplayService {
    pub fn new(
        store: Arc<dyn ReplayStorePort>,
        server_secret: [u8; 32],
        lineage_id: EventLogLineageId,
        authorization: Arc<dyn ReplayAuthorizationPort>,
    ) -> Self {
        Self {
            store,
            authorization,
            server_secret,
            lineage_id,
        }
    }

    fn authorization_request(
        principal_id: &str,
        session_generation: i64,
        authority_id: &[u8; 16],
        expected_epoch: i64,
        aggregate_type: i32,
        aggregate_id: &[u8; 16],
    ) -> Result<ReplayAuthorizationRequest, ReplayError> {
        Ok(ReplayAuthorizationRequest {
            principal_id: principal_id.to_owned(),
            authority_id: *authority_id,
            session_generation,
            expected_epoch,
            session_id: None,
            scope: Some(ReplayScope::Aggregate {
                aggregate_type: u8::try_from(aggregate_type).map_err(|_| {
                    ReplayError::Integrity("invalid replay authorization scope".to_owned())
                })?,
                aggregate_id: *aggregate_id,
            }),
        })
    }

    fn session_authorization_request(
        session_id: &[u8; 16],
        principal_id: &str,
        session_generation: i64,
        authority_id: &[u8; 16],
        expected_epoch: i64,
    ) -> ReplayAuthorizationRequest {
        ReplayAuthorizationRequest {
            principal_id: principal_id.to_owned(),
            authority_id: *authority_id,
            session_generation,
            expected_epoch,
            session_id: Some(*session_id),
            scope: None,
        }
    }

    /// NM-06 pre-delivery gate for session requests: resolves the session's
    /// delivery scope OUTSIDE any store transaction, then re-checks the
    /// CURRENT trust admission for conversation-scoped sessions (fail-closed
    /// on authority errors). Task-run and unknown sessions fall through to
    /// the store's own handling.
    async fn nm06_session_delivery_gate(
        &self,
        session_id: &[u8; 16],
        principal_id: &str,
        generation: i64,
        authority_id: &[u8; 16],
        epoch: i64,
    ) -> Result<(), ReplayError> {
        // Unknown session: fall through to the store's own not-found handling.
        let Some((aggregate_type, aggregate_id)) = self.store.session_delivery_scope(session_id)
        else {
            return Ok(());
        };
        let scope_request = Self::authorization_request(
            principal_id,
            generation,
            authority_id,
            epoch,
            aggregate_type,
            &aggregate_id,
        )?;
        self.authorization.current_lease(&scope_request)?;
        Ok(())
    }

    fn acquire_lease(
        &self,
        request: &ReplayAuthorizationRequest,
    ) -> Result<ReplayAuthorizationLease, ReplayError> {
        let lease = self.authorization.current_lease(request)?;
        if lease.principal_id() != request.principal_id
            || lease.authorization_epoch() != request.expected_epoch
        {
            return Err(ReplayError::AuthorizationRevoked);
        }
        Ok(lease)
    }

    fn authorized_guard(
        &self,
        request: ReplayAuthorizationRequest,
        lease: ReplayAuthorizationLease,
        delegate: Arc<dyn ReplayDeliveryPrecommitGuard>,
    ) -> Arc<dyn ReplayDeliveryPrecommitGuard> {
        Arc::new(AuthorizedDeliveryGuard {
            authorization: Arc::clone(&self.authorization),
            request,
            lease,
            delegate,
        })
    }

}
