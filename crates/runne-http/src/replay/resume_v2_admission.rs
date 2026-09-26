async fn owned_resume_admission(
    state: &ReplayHttpState,
    principal_id: String,
    scope: ReplayScope,
    wire: runne_api::ReplayRetentionBaselineWireV2,
    context: runne_application::local_session::AuthenticatedReplayResumeContextV2,
    delivery_guard: Arc<dyn ReplayDeliveryPrecommitGuard>,
    permit: ReplayCountPermit,
    binding: ReplayHttpBinding,
) -> Result<
    (
        ReplaySession,
        Vec<ReplayEvent>,
        runne_domain::replay::ReplayCursor,
        runne_application::ports::ReplayAcceptedPromotionV2,
    ),
    ReplayError,
> {
    let service = Arc::clone(&state.service);
    let owned_state = state.clone();
    let delivery_deadline =
        resume_delivery_deadline(wire.to_unauthenticated_fields().expires_at_unix_ms);
    let (sender, receiver) = tokio::sync::oneshot::channel();
    tokio::spawn(async move {
        let result = service
            .resume_from_retention_baseline_v2(
                &principal_id,
                binding.session_generation,
                &binding.authority_id,
                binding.authorization_epoch,
                &scope,
                &wire,
                context,
                delivery_guard,
            )
            .await;
        let result = match result {
            Ok(result) => {
                let session_id = result.0.session_id;
                owned_state
                    .retain_v2_session_permit(
                        session_id,
                        principal_id.clone(),
                        permit,
                        delivery_deadline,
                        binding,
                    )
                    .map(|()| result)
                    .map_err(replay_http_failure_to_delivery_error)
            }
            Err(error) => Err(error),
        };
        if let Err(Ok((session, _, _, _))) = sender.send(result) {
            owned_state.begin_v2_resume_reaping(session.session_id, principal_id);
        }
    });
    receiver
        .await
        .map_err(|_| ReplayError::Storage("V2 resume admission task stopped".to_owned()))?
}
