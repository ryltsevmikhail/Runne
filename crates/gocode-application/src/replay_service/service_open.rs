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
        self.open_session_with_baseline_context(
            principal_id,
            session_generation,
            authority_id,
            authorization_epoch,
            aggregate_type,
            aggregate_id,
            from_cursor,
            delivery_guard,
            None,
            false,
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn open_session_with_baseline_context(
        &self,
        principal_id: &str,
        session_generation: i64,
        authority_id: &[u8; 16],
        authorization_epoch: i64,
        aggregate_type: i32,
        aggregate_id: &[u8; 16],
        from_cursor: Option<ReplayCursor>,
        delivery_guard: Arc<dyn ReplayDeliveryPrecommitGuard>,
        issuance: Option<&crate::local_session::AuthenticatedReplayResumeContextV2>,
        issue_v2: bool,
    ) -> Result<(ReplaySession, Vec<ReplayEvent>), ReplayError> {
        if let Some(cursor) = &from_cursor {
            self.validate_cursor_integrity(cursor)?;
            if !matches!(&cursor.scope, ReplayScope::Aggregate { aggregate_type: kind, aggregate_id: id }
                if i32::from(*kind) == aggregate_type && id == aggregate_id)
            {
                return Err(ReplayError::CursorInvalid {
                    reason: "cursor scope mismatch".to_owned(),
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
            ReplayOpenResult::RetentionGap { baseline } => {
                let current = self.acquire_lease(&request)?;
                if current != lease {
                    return Err(ReplayError::AuthorizationRevoked);
                }
                if current.sensitivity_ceiling() != Sensitivity::Sensitive {
                    return Err(ReplayError::SensitivityDenied);
                }
                let Some(context) = issuance else {
                    return Err(ReplayError::Integrity(
                        "retention baseline requires authenticated issuance".to_owned(),
                    ));
                };
                let scope = ReplayScope::Aggregate {
                    aggregate_type: u8::try_from(aggregate_type).map_err(|_| {
                        ReplayError::Integrity("invalid replay aggregate type".to_owned())
                    })?,
                    aggregate_id: *aggregate_id,
                };
                let issued_at = context
                    .now_unix_ms()
                    .map_err(|_| ReplayError::AuthorizationRevoked)?;
                let wire = context
                    .issuer()
                    .issue(
                        scope,
                        baseline,
                        context.now_monotonic(),
                        issued_at,
                        issued_at.saturating_add(30_000),
                    )
                    .map_err(|_| ReplayError::AuthorizationRevoked)?;
                Err(ReplayError::ReplayRetentionGap {
                    baseline: Box::new(wire),
                })
            }
            ReplayOpenResult::RetentionGapWithV2 {
                baseline,
                baseline_v2,
            } => {
                if !issue_v2 {
                    let current = self.acquire_lease(&request)?;
                    if current != lease {
                        return Err(ReplayError::AuthorizationRevoked);
                    }
                    if current.sensitivity_ceiling() != Sensitivity::Sensitive {
                        return Err(ReplayError::SensitivityDenied);
                    }
                    let context = issuance.ok_or_else(|| {
                        ReplayError::Integrity(
                            "retention baseline requires authenticated issuance".to_owned(),
                        )
                    })?;
                    let scope = ReplayScope::Aggregate {
                        aggregate_type: u8::try_from(aggregate_type).map_err(|_| {
                            ReplayError::Integrity("invalid replay aggregate type".to_owned())
                        })?,
                        aggregate_id: *aggregate_id,
                    };
                    let issued_at = context
                        .now_unix_ms()
                        .map_err(|_| ReplayError::AuthorizationRevoked)?;
                    let wire = context
                        .issuer()
                        .issue(
                            scope,
                            baseline,
                            context.now_monotonic(),
                            issued_at,
                            issued_at.saturating_add(30_000),
                        )
                        .map_err(|_| ReplayError::AuthorizationRevoked)?;
                    return Err(ReplayError::ReplayRetentionGap {
                        baseline: Box::new(wire),
                    });
                }
                let current = self.acquire_lease(&request)?;
                if current != lease {
                    return Err(ReplayError::AuthorizationRevoked);
                }
                if current.sensitivity_ceiling() != Sensitivity::Sensitive {
                    return Err(ReplayError::SensitivityDenied);
                }
                let context = issuance.ok_or_else(|| {
                    ReplayError::Integrity(
                        "V2 retention baseline requires authenticated issuance".to_owned(),
                    )
                })?;
                let scope = ReplayScope::Aggregate {
                    aggregate_type: u8::try_from(aggregate_type).map_err(|_| {
                        ReplayError::Integrity("invalid replay aggregate type".to_owned())
                    })?,
                    aggregate_id: *aggregate_id,
                };
                let issued_at = context
                    .now_unix_ms()
                    .map_err(|_| ReplayError::AuthorizationRevoked)?;
                let wire = context
                    .issuer()
                    .issue_v2(
                        scope,
                        *baseline_v2,
                        context.now_monotonic(),
                        issued_at,
                        issued_at.saturating_add(30_000),
                    )
                    .map_err(|_| ReplayError::AuthorizationRevoked)?;
                Err(ReplayError::ReplayRetentionGapV2 {
                    baseline: Box::new(wire),
                })
            }
        }
    }
}
