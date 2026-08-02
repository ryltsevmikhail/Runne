impl ReplayService {
    #[allow(clippy::too_many_arguments)]
    pub async fn open_session(
        &self,
        principal_id: &str,
        session_generation: i64,
        authority_id: &[u8; 16],
        authorization_epoch: i64,
        aggregate_type: i32,
        aggregate_id: &[u8; 16],
        from_cursor: Option<ReplayCursor>,
        delivery_guard: Arc<dyn ReplayDeliveryPrecommitGuard>,
    ) -> Result<(ReplaySession, Vec<ReplayEvent>), ReplayError> {
        if let Some(cursor) = &from_cursor {
            self.validate_cursor_integrity(cursor)?;
            if !matches!(
                &cursor.scope,
                ReplayScope::Aggregate { aggregate_type: cursor_type, aggregate_id: cursor_id }
                    if i32::from(*cursor_type) == aggregate_type && cursor_id == aggregate_id
            ) {
                return Err(ReplayError::CursorInvalid {
                    reason: "cursor scope mismatch".to_string(),
                });
            }
        }
        let request = Self::authorization_request(
            principal_id,
            session_generation,
            authority_id,
            authorization_epoch,
            aggregate_type,
            aggregate_id,
        )?;
        let lease = self.acquire_lease(&request)?;
        let result = self
            .store
            .open_session(
                principal_id,
                session_generation,
                authority_id,
                lease.authorization_epoch(),
                aggregate_type,
                aggregate_id,
                from_cursor.as_ref(),
                &self.lineage_id,
                &self.server_secret,
                self.authorized_guard(request.clone(), lease.clone(), delivery_guard),
            )
            .await?;
        match result {
            ReplayOpenResult::Opened { session, events } => Ok((session, events)),
            ReplayOpenResult::RetentionGap {
                floor_event,
                gap_range_ref,
            } => {
                let current_lease = self.acquire_lease(&request)?;
                if current_lease != lease {
                    return Err(ReplayError::AuthorizationRevoked);
                }
                let sensitivity_ceiling = current_lease.sensitivity_ceiling();
                let floor_cursor = floor_event
                    .filter(|event| {
                        let rank = |value| match value {
                            Sensitivity::Public => 0,
                            Sensitivity::Internal => 1,
                            Sensitivity::Sensitive => 2,
                        };
                        rank(match event.sensitivity {
                            0 => Sensitivity::Public,
                            1 => Sensitivity::Internal,
                            2 => Sensitivity::Sensitive,
                            _ => return false,
                        }) <= rank(sensitivity_ceiling)
                    })
                    .map(|event| {
                        self.build_cursor(
                            &event,
                            &ReplayScope::Aggregate {
                                aggregate_type: u8::try_from(aggregate_type).unwrap_or_default(),
                                aggregate_id: *aggregate_id,
                            },
                        )
                    })
                    .transpose()?;
                Err(ReplayError::ReplayRetentionGap {
                    floor_cursor: floor_cursor.map(Box::new),
                    gap_range_ref,
                })
            }
        }
    }

}
