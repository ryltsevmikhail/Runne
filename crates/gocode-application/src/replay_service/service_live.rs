impl ReplayService {
    pub async fn continue_live(
        &self,
        session_id: &[u8; 16],
        principal_id: &str,
        generation: i64,
        authority_id: &[u8; 16],
        epoch: i64,
    ) -> Result<ReplaySession, ReplayError> {
        let request = Self::session_authorization_request(
            session_id,
            principal_id,
            generation,
            authority_id,
            epoch,
        );
        let lease = self.acquire_lease(&request)?;
        self.store
            .continue_live(
                session_id,
                principal_id,
                generation,
                authority_id,
                lease.authorization_epoch(),
                self.authorized_guard(request, lease, Arc::new(NoopDeliveryGuard)),
            )
            .await
    }

    pub async fn poll_live(
        &self,
        session_id: &[u8; 16],
        principal_id: &str,
        generation: i64,
        authority_id: &[u8; 16],
        epoch: i64,
        delivery_guard: Arc<dyn ReplayDeliveryPrecommitGuard>,
    ) -> Result<(ReplaySession, Vec<ReplayEvent>), ReplayError> {
        let request = Self::session_authorization_request(
            session_id,
            principal_id,
            generation,
            authority_id,
            epoch,
        );
        let lease = self.acquire_lease(&request)?;
        self.store
            .poll_live(
                session_id,
                principal_id,
                generation,
                authority_id,
                lease.authorization_epoch(),
                self.authorized_guard(request, lease, delivery_guard),
            )
            .await
    }

    pub async fn close_session(
        &self,
        session_id: &[u8; 16],
        principal_id: &str,
        generation: i64,
        authority_id: &[u8; 16],
        epoch: i64,
    ) -> Result<(), ReplayError> {
        self.store
            .close_session(session_id, principal_id, generation, authority_id, epoch)
            .await
    }

}
