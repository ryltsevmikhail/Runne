impl ReplayService {
    #[allow(clippy::too_many_arguments)]
    pub async fn resume_from_retention_baseline_v2(
        &self,
        principal_id: &str,
        session_generation: i64,
        authority_id: &[u8; 16],
        authorization_epoch: i64,
        scope: &ReplayScope,
        wire: &gocode_api::ReplayRetentionBaselineWireV2,
        context: crate::local_session::AuthenticatedReplayResumeContextV2,
        delivery_guard: Arc<dyn ReplayDeliveryPrecommitGuard>,
    ) -> Result<(ReplaySession, Vec<ReplayEvent>, ReplayCursor, ReplayAcceptedPromotionV2), ReplayError> {
        let (aggregate_type, aggregate_id) = match scope {
            ReplayScope::Aggregate {
                aggregate_type,
                aggregate_id,
            } if matches!(aggregate_type, 1 | 2) => (i32::from(*aggregate_type), *aggregate_id),
            _ => {
                return Err(ReplayError::Integrity(
                    "invalid V2 replay resume scope".to_owned(),
                ));
            }
        };
        let request = Self::authorization_request(
            principal_id,
            session_generation,
            authority_id,
            authorization_epoch,
            aggregate_type,
            &aggregate_id,
        )?;
        let lease = self.acquire_lease(&request)?;
        if lease.sensitivity_ceiling() != Sensitivity::Sensitive {
            return Err(ReplayError::SensitivityDenied);
        }
        let claims = context
            .issuer()
            .verify_v2_for_resume(
                scope,
                wire,
                context.now_monotonic(),
                context
                    .now_unix_ms()
                    .map_err(|_| ReplayError::AuthorizationRevoked)?,
            )
            .map_err(|_| ReplayError::AuthorizationRevoked)?;
        let candidate = ReplayRetentionBaselineCandidateV2::from_storage(
            ReplayRetentionBaselineCandidateV2Parts {
                promotion_projection_bytes: claims.promotion_projection_bytes().to_vec(),
                sequence: claims.sequence(),
                version: claims.version(),
                baseline_global_position: claims.baseline_global_position(),
                head_event_id: claims.head_event_id(),
                head_integrity_digest: claims.head_integrity_digest(),
                retained_floor: claims.retained_floor(),
                captured_high_water: claims.captured_high_water(),
                retention_generation: claims.retention_generation(),
                retention_manifest_digest: claims.retention_manifest_digest(),
            },
        )
        .map_err(|_| ReplayError::AuthorizationRevoked)?;
        let reissued_at = context
            .now_unix_ms()
            .map_err(|_| ReplayError::AuthorizationRevoked)?;
        let reissued_wire = context
            .issuer()
            .issue_v2(
                scope.clone(),
                candidate,
                context.now_monotonic(),
                reissued_at,
                reissued_at.saturating_add(30_000),
            )
            .map_err(|_| ReplayError::AuthorizationRevoked)?;
        let resume_request = ReplayBaselineResumeRequestV2::from_authenticated(
            principal_id,
            session_generation,
            *authority_id,
            lease.authorization_epoch(),
            claims,
        );
        let (session, events, baseline_event, accepted) = self
            .store
            .resume_session_from_baseline_v2(
                resume_request,
                &self.lineage_id,
                &self.server_secret,
                Arc::new(ResumeV2PrecommitGuard {
                    authorization: Arc::clone(&self.authorization),
                    request,
                    lease,
                    context,
                    scope: scope.clone(),
                    wire: wire.clone(),
                    reissued_wire,
                    delegate: delivery_guard,
                }),
            )
            .await?;
        let baseline_cursor = self.build_cursor(&baseline_event, scope)?;
        Ok((session, events, baseline_cursor, accepted))
    }
}

struct ResumeV2PrecommitGuard {
    authorization: Arc<dyn ReplayAuthorizationPort>,
    request: ReplayAuthorizationRequest,
    lease: ReplayAuthorizationLease,
    context: crate::local_session::AuthenticatedReplayResumeContextV2,
    scope: ReplayScope,
    wire: gocode_api::ReplayRetentionBaselineWireV2,
    reissued_wire: gocode_api::ReplayRetentionBaselineWireV2,
    delegate: Arc<dyn ReplayDeliveryPrecommitGuard>,
}

impl ResumeV2PrecommitGuard {
    fn revalidate(&self) -> Result<(), ReplayError> {
        let current = self.authorization.current_lease(&self.request)?;
        self.revalidate_under_locked_lease(&current)
    }

    fn revalidate_under_locked_lease(
        &self,
        current: &ReplayAuthorizationLease,
    ) -> Result<(), ReplayError> {
        if current != &self.lease {
            return Err(ReplayError::AuthorizationRevoked);
        }
        if current.sensitivity_ceiling() != Sensitivity::Sensitive {
            return Err(ReplayError::SensitivityDenied);
        }
        self.context
            .issuer()
            .verify_v2_for_resume(
                &self.scope,
                &self.wire,
                self.context.now_monotonic(),
                self.context
                    .now_unix_ms()
                    .map_err(|_| ReplayError::AuthorizationRevoked)?,
            )
            .map_err(|_| ReplayError::AuthorizationRevoked)?;
        self.context
            .issuer()
            .verify_v2_for_resume(
                &self.scope,
                &self.reissued_wire,
                self.context.now_monotonic(),
                self.context
                    .now_unix_ms()
                    .map_err(|_| ReplayError::AuthorizationRevoked)?,
            )
            .map(|_| ())
            .map_err(|_| ReplayError::AuthorizationRevoked)
    }
}

impl ReplayDeliveryPrecommitGuard for ResumeV2PrecommitGuard {
    fn inspect(&self, session: &ReplaySession, events: &[ReplayEvent]) -> Result<(), ReplayError> {
        self.revalidate()?;
        self.delegate.inspect(session, events)?;
        self.revalidate()
    }

    fn inspect_event(
        &self,
        session: &ReplaySession,
        event: &ReplayEvent,
    ) -> Result<(), ReplayError> {
        self.revalidate()?;
        self.delegate.inspect_event(session, event)?;
        self.revalidate()
    }

    fn mutate_session_admission(
        &self,
        session: &ReplaySession,
        events: &[ReplayEvent],
        mutation: &mut dyn FnMut() -> Result<ReplaySession, ReplayError>,
    ) -> Result<ReplaySession, ReplayError> {
        self.authorization
            .mutate_session_admission(&self.request, &mut |current| {
                self.revalidate_under_locked_lease(current)?;
                self.delegate.inspect(session, events)?;
                self.revalidate_under_locked_lease(current)?;
                mutation()
            })
    }
}
