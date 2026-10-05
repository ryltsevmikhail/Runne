use super::super::route::{ExecutionRoute, RouteAdmission};
use super::super::*;
use crate::canonical_provider::projection::{
    map_admission_error, map_existing_state, provider_idempotency_key,
};
use runne_provider::ProviderRecoveryDispatchContextProvider;
use runne_store::provider::CredentialDispatchAuthority;

pub(super) async fn start(
    service: &DaemonCanonicalProviderService,
    job: &CanonicalProviderExecutionJob,
    route: &ExecutionRoute<'_>,
    assignment: Option<&runne_application::ports::TaskRunAssignmentIdentity>,
    round: Option<&super::super::D2ProviderRound>,
    call: ProviderCall,
    round_call_id: Option<ProviderCallId>,
) -> Result<
    Box<runne_store::provider::VersionedProviderExecutionBinding>,
    CanonicalProviderExecutionError,
> {
    let (requested_input_tokens, requested_output_tokens, max_cost_micros) =
        super::super::route::request_ceiling(route.profile.as_ref())?;
    let provider_identity = ProviderId::new(route.provider_id)
        .map_err(|_| CanonicalProviderExecutionError::RejectedBeforeEffect)?;
    let request_intents: Arc<dyn ProviderRecoveryDispatchContextProvider> = Arc::new(
        runne_runtime::provider_execution::RuntimeProviderRemoteIdentityCommitter::new(
            Arc::clone(&service.keyring),
            Arc::clone(&service.execution_store),
        ),
    );
    let credential = CredentialDispatchAuthority::new(
        route.credential_store.as_ref(),
        &service.launch_capability,
    );
    let effect = super::super::dispatch_binding::OnlineDispatchFence::new(
        super::super::dispatch_binding::OnlineDispatchFenceConfig {
            authority: credential,
            inner: route.adapter,
            trust: service.trust.as_ref().map(|trust| {
                (
                    trust.clone(),
                    job.context.principal_id.0.clone(),
                    job.started.conversation_id,
                )
            }),
            taskrun: (!route.tool_mode)
                .then(|| assignment.cloned())
                .flatten()
                .map(|identity| {
                    (
                        identity,
                        job.started.taskrun_version,
                        route.profile.profile_digest(),
                    )
                }),
            taskrun_round: assignment
                .cloned()
                .zip(round.cloned())
                .map(|(identity, round)| {
                    (
                        identity,
                        job.started.taskrun_version,
                        round,
                        route.profile.profile_digest(),
                    )
                }),
            taskrun_store: &service.conversation_store,
            request_intents,
            provider_id: provider_identity.clone(),
            credential_realm: provider_identity,
            profile_id: route.profile.profile_id().to_owned(),
        },
    );
    let coordinator = SqliteProviderDispatchCoordinator::new_with_budget(
        service.dispatch_store.as_ref(),
        service.execution_store.as_ref(),
        credential,
        route.adapter,
        &effect,
        service.prohibited_content.as_ref(),
        runne_api::is_subscription_provider(route.provider_id),
        Some(route.credential_store.clone()),
    );
    service.renew_launch_authority()?;
    let request = ProviderCoordinatorRequest {
        call,
        principal_id: job.context.principal_id.0.clone(),
        conversation_id: job.started.conversation_id,
        taskrun_id: job.started.taskrun_id,
        execution_attempt_id: job.started.attempt_id,
        profile_digest: route.profile.profile_digest(),
        pricing_revision_digest: route.profile.pricing_revision_digest(),
        requested_input_tokens,
        requested_output_tokens,
        max_cost_micros,
        currency: route.profile.currency().to_owned(),
        provider_idempotency_key: round_call_id.map_or_else(
            || provider_idempotency_key(job),
            |id| format!("gocode-d2-round-{}", hex::encode(id.as_bytes())),
        ),
    };
    let outcome = match route.admission {
        RouteAdmission::Primary => coordinator.dispatch(request).await,
        RouteAdmission::Secondary(grant) => {
            coordinator.dispatch_secondary_profile(request, grant).await
        }
    };
    match outcome {
        Ok(ProviderCoordinatorOutcome::Streaming { binding }) => {
            execution_diagnostics::record("provider_dispatch", true);
            Ok(binding)
        }
        Ok(ProviderCoordinatorOutcome::Uncertain) => {
            execution_diagnostics::record("provider_dispatch", false);
            Err(CanonicalProviderExecutionError::Uncertain)
        }
        Ok(ProviderCoordinatorOutcome::RejectedBeforeEffect { .. }) => {
            execution_diagnostics::record("provider_dispatch", false);
            Err(CanonicalProviderExecutionError::RejectedBeforeEffect)
        }
        Ok(ProviderCoordinatorOutcome::Existing { state }) => Err(map_existing_state(state)),
        Err(error) => {
            execution_diagnostics::record(
                execution_diagnostics::admission_failure_stage(&error),
                false,
            );
            Err(map_admission_error(error))
        }
    }
}
