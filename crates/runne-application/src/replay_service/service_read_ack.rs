impl ReplayService {
    /// Читает следующую страницу; cursor каждого event строится transport adapter через `build_cursor_from_event`.
    #[allow(clippy::too_many_arguments)]
    pub async fn read_page(
        &self,
        session_id: &[u8; 16],
        principal_id: &str,
        generation: i64,
        authority_id: &[u8; 16],
        epoch: i64,
        limit: usize,
        delivery_guard: Arc<dyn ReplayDeliveryPrecommitGuard>,
    ) -> Result<(ReplaySession, Vec<ReplayEvent>), ReplayError> {
        let request = Self::session_authorization_request(
            session_id,
            principal_id,
            generation,
            authority_id,
            epoch,
        );
        self.nm06_session_delivery_gate(session_id, principal_id, generation, authority_id, epoch)
            .await?;
        let lease = self.acquire_lease(&request)?;
        self.store
            .read_page(
                session_id,
                principal_id,
                generation,
                authority_id,
                lease.authorization_epoch(),
                limit,
                self.authorized_guard(request, lease, delivery_guard),
            )
            .await
    }

    /// Подтверждает cursor после проверки его integrity на application boundary.
    pub async fn acknowledge(
        &self,
        session_id: &[u8; 16],
        principal_id: &str,
        generation: i64,
        authority_id: &[u8; 16],
        epoch: i64,
        cursor: &ReplayCursor,
    ) -> Result<(), ReplayError> {
        self.validate_cursor_integrity(cursor)?;
        let request = Self::authorization_request(
            principal_id,
            generation,
            authority_id,
            epoch,
            match &cursor.scope {
                ReplayScope::Aggregate { aggregate_type, .. } => i32::from(*aggregate_type),
                _ => {
                    return Err(ReplayError::CursorInvalid {
                        reason: "unsupported acknowledgement scope".to_owned(),
                    });
                }
            },
            match &cursor.scope {
                ReplayScope::Aggregate { aggregate_id, .. } => aggregate_id,
                _ => unreachable!("scope was checked above"),
            },
        )?;
        let lease = self.acquire_lease(&request)?;
        self.store
            .acknowledge(
                session_id,
                principal_id,
                generation,
                authority_id,
                lease.authorization_epoch(),
                cursor,
                self.authorized_guard(request, lease, Arc::new(NoopDeliveryGuard)),
            )
            .await
    }

}
