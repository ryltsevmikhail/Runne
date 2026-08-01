impl<S, V, D, C> MigrationRouter<S, V, D, C>
where
    S: MigrationControlStore + MigrationRoutingStore,
    V: FenceValidationPort,
    D: MigrationDispatchPort,
    C: Clock + Send + Sync,
{
    /// Route one new-work command exactly once for this process.
    ///
    /// Cross-process uncertainty remains fail-closed through the durable
    /// `Indeterminate` state and is never reclaimed automatically.
    pub async fn route_new_work(
        &self,
        request: RouteNewWorkRequest,
    ) -> Result<RouteDecision, MigrationRoutingError> {
        validate_request(&request)?;
        let aggregate_lock = self.aggregate_lock(&request.aggregate_id)?;
        let guard = aggregate_lock.lock().await;
        let result = self.route_exclusive(request.clone()).await;
        drop(guard);
        self.release_aggregate_lock(&request.aggregate_id, &aggregate_lock)?;
        result
    }

    async fn route_exclusive(
        &self,
        request: RouteNewWorkRequest,
    ) -> Result<RouteDecision, MigrationRoutingError> {
        let existing = self
            .store
            .load_runtime_binding(request.aggregate_id.clone(), &request.routing_unit)
            .map_err(MigrationRoutingError::Store)?;
        let (binding, intent) = if let Some(binding) = existing {
            let intent = self
                .store
                .load_dispatch_intent(request.aggregate_id.clone())
                .map_err(MigrationRoutingError::Store)?
                .ok_or(MigrationRoutingError::Store(
                    MigrationStoreError::IntegrityViolation,
                ))?;
            validate_existing_intent(&intent, &request)?;
            (binding, intent)
        } else {
            let snapshot = self
                .store
                .load_routing_head(&request.routing_unit)
                .map_err(MigrationRoutingError::Store)?
                .ok_or(MigrationRoutingError::RoutingHeadNotFound)?;
            let fallback_policy = self.select_pre_dispatch_policy(&snapshot.authority, &request)?;
            self.fence
                .validate_ingress(snapshot.routing_generation, snapshot.fencing_token)
                .map_err(MigrationRoutingError::Fence)?;
            let bound_at = self.clock.now().map_err(MigrationRoutingError::Clock)?;
            let admission = self
                .store
                .bind_and_create_dispatch_intent(BindRuntimeRequest {
                    aggregate_id: request.aggregate_id.clone(),
                    routing_unit: request.routing_unit.clone(),
                    expected_snapshot: snapshot,
                    fallback_policy,
                    command_id: request.command_id,
                    idempotency_key: request.idempotency_key.clone(),
                    request_digest: request.request_digest,
                    bound_at,
                })
                .map_err(MigrationRoutingError::Store)?;
            (admission.binding().clone(), admission.intent().clone())
        };

        match intent.status {
            DispatchIntentStatus::Accepted => {
                return Ok(RouteDecision {
                    binding,
                    dispatch_status: intent.status,
                });
            }
            DispatchIntentStatus::RejectedBeforeAcceptance => {
                return Err(MigrationRoutingError::RejectedBeforeAcceptance);
            }
            DispatchIntentStatus::Indeterminate => {
                return Err(MigrationRoutingError::ReconciliationRequired);
            }
            DispatchIntentStatus::Pending => {}
        }

        self.dispatch_pending(binding, intent).await
    }

    fn select_pre_dispatch_policy(
        &self,
        authority: &RuntimeAuthority,
        request: &RouteNewWorkRequest,
    ) -> Result<PreDispatchFallbackPolicy, MigrationRoutingError> {
        if self.legacy_admission_policy == LegacyAdmissionPolicy::Closed
            && (matches!(authority, RuntimeAuthority::Source(_))
                || request.authority_preference == RouteAuthorityPreference::LegacySource)
        {
            return Err(MigrationRoutingError::LegacyAdmissionClosed);
        }
        if !matches!(authority, RuntimeAuthority::Candidate(_)) {
            return Ok(PreDispatchFallbackPolicy::Disabled);
        }
        if request.authority_preference == RouteAuthorityPreference::LegacySource {
            self.fallback_policy
                .validate_routing_unit(&request.routing_unit)
                .map_err(|_| MigrationRoutingError::RoutingUnitMismatch)?;
            return match &self.fallback_policy {
                PreDispatchFallbackPolicy::ExplicitSourceBeforeAcceptance { .. } => {
                    Ok(self.fallback_policy.clone())
                }
                PreDispatchFallbackPolicy::Disabled => {
                    Err(MigrationRoutingError::RoutingUnitMismatch)
                }
            };
        }
        match validate_candidate_claim(authority, request, &self.features) {
            Ok(()) => Ok(PreDispatchFallbackPolicy::Disabled),
            Err(error @ MigrationRoutingError::Feature(_)) => {
                self.fallback_policy
                    .validate_routing_unit(&request.routing_unit)
                    .map_err(|_| MigrationRoutingError::RoutingUnitMismatch)?;
                match &self.fallback_policy {
                    PreDispatchFallbackPolicy::ExplicitSourceBeforeAcceptance { .. } => {
                        Ok(self.fallback_policy.clone())
                    }
                    PreDispatchFallbackPolicy::Disabled => Err(error),
                }
            }
            Err(error) => Err(error),
        }
    }
}
