impl ReplayService {
    /// Завершает catch-up и возвращает server-issued proof.
    pub async fn complete_catch_up(
        &self,
        session_id: &[u8; 16],
        principal_id: &str,
        generation: i64,
        authority_id: &[u8; 16],
        epoch: i64,
    ) -> Result<CatchUpCompletion, ReplayError> {
        let request = Self::session_authorization_request(
            session_id,
            principal_id,
            generation,
            authority_id,
            epoch,
        );
        let lease = self.acquire_lease(&request)?;
        let (session, last_ack_event) = self
            .store
            .complete_catch_up(
                session_id,
                principal_id,
                generation,
                authority_id,
                lease.authorization_epoch(),
                &self.server_secret,
                self.authorized_guard(request, lease, Arc::new(NoopDeliveryGuard)),
            )
            .await?;
        let scope = ReplayScope::Aggregate {
            aggregate_type: u8::try_from(session.aggregate_type)
                .map_err(|_| ReplayError::Integrity("invalid completed replay scope".to_owned()))?,
            aggregate_id: session.aggregate_id,
        };
        let last_ack_cursor = last_ack_event
            .as_ref()
            .map(|event| self.build_cursor(event, &scope))
            .transpose()?;
        let proof = session.catch_up_completion.ok_or_else(|| {
            ReplayError::Integrity("missing catch-up completion proof".to_string())
        })?;
        if proof.len() != 32 {
            return Err(ReplayError::Integrity(
                "invalid catch-up completion proof length".to_string(),
            ));
        }
        let mut proof_bytes = [0; 32];
        proof_bytes.copy_from_slice(&proof);
        Ok(CatchUpCompletion {
            session_id: session.session_id,
            high_water_ref: session.high_water_ref,
            last_ack_cursor,
            proof: IntegrityDigest::from_bytes(proof_bytes),
        })
    }

}
