impl<S, V, D, C> MigrationRouter<S, V, D, C>
where
    S: MigrationControlStore + MigrationRoutingStore,
    V: FenceValidationPort,
    D: MigrationDispatchPort,
    C: Clock + Send + Sync,
{
    async fn dispatch_pending(
        &self,
        binding: RuntimeBinding,
        intent: RoutingDispatchIntent,
    ) -> Result<RouteDecision, MigrationRoutingError> {
        let claimed_at = self.clock.now().map_err(MigrationRoutingError::Clock)?;
        let claim = self
            .store
            .claim_dispatch(binding.aggregate_id.clone(), intent.command_id, claimed_at)
            .map_err(MigrationRoutingError::Store)?;
        let claimed = match claim {
            DispatchClaim::Claimed(claimed) => claimed,
            DispatchClaim::Existing(existing) => {
                return terminal_decision(binding, existing.status);
            }
        };
        if claimed.status != DispatchIntentStatus::Indeterminate {
            return Err(MigrationRoutingError::Store(
                MigrationStoreError::IntegrityViolation,
            ));
        }
        let admitted = self
            .fence
            .validate_ingress(binding.routing_generation, binding.fencing_token)
            .map_err(MigrationRoutingError::Fence)?;
        if self.fence.validate_worker_dispatch(&admitted).is_err() {
            let recorded_at = self.clock.now().map_err(MigrationRoutingError::Clock)?;
            let recorded = self
                .store
                .record_dispatch_result(
                    binding.aggregate_id.clone(),
                    intent.command_id,
                    DispatchResultStatus::RejectedBeforeAcceptance,
                    recorded_at,
                )
                .map_err(MigrationRoutingError::Store)?;
            if recorded.status != DispatchIntentStatus::RejectedBeforeAcceptance {
                return Err(MigrationRoutingError::Store(
                    MigrationStoreError::IntegrityViolation,
                ));
            }
            return Err(MigrationRoutingError::RejectedBeforeAcceptance);
        }

        match self
            .dispatch
            .dispatch(binding.clone(), intent.command_id)
            .await
        {
            DispatchAttempt::Indeterminate | DispatchAttempt::AcceptedThenFailed => {
                Err(MigrationRoutingError::ReconciliationRequired)
            }
            DispatchAttempt::RejectedBeforeAcceptance => {
                let recorded_at = self.clock.now().map_err(MigrationRoutingError::Clock)?;
                let recorded = self
                    .store
                    .record_dispatch_result(
                        binding.aggregate_id.clone(),
                        intent.command_id,
                        DispatchResultStatus::RejectedBeforeAcceptance,
                        recorded_at,
                    )
                    .map_err(|_| MigrationRoutingError::ReconciliationRequired)?;
                if recorded.status != DispatchIntentStatus::RejectedBeforeAcceptance {
                    return Err(MigrationRoutingError::ReconciliationRequired);
                }
                Err(MigrationRoutingError::RejectedBeforeAcceptance)
            }
            DispatchAttempt::Accepted => {
                self.fence
                    .validate_confirmation(&admitted)
                    .map_err(|_| MigrationRoutingError::ReconciliationRequired)?;
                let recorded_at = self.clock.now().map_err(MigrationRoutingError::Clock)?;
                let recorded = self
                    .store
                    .record_dispatch_result(
                        binding.aggregate_id.clone(),
                        intent.command_id,
                        DispatchResultStatus::Accepted,
                        recorded_at,
                    )
                    .map_err(|_| MigrationRoutingError::ReconciliationRequired)?;
                if recorded.status != DispatchIntentStatus::Accepted {
                    return Err(MigrationRoutingError::ReconciliationRequired);
                }
                Ok(RouteDecision {
                    binding,
                    dispatch_status: recorded.status,
                })
            }
        }
    }
}
