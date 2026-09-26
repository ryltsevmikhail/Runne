struct CurrentEpochAuthorization {
    epoch: i64,
    authority: [u8; 16],
    generation: i64,
}

impl ReplayAuthorizationPort for CurrentEpochAuthorization {
    fn current_lease(
        &self,
        request: &ReplayAuthorizationRequest,
    ) -> Result<ReplayAuthorizationLease, ReplayError> {
        if request.authority_id != self.authority || request.session_generation != self.generation {
            return Err(ReplayError::AuthorizationRevoked);
        }
        ReplayAuthorizationLease::new(
            request.principal_id.clone(),
            self.epoch,
            Sensitivity::Sensitive,
        )
    }
}

fn binding_at_epoch(epoch: u64) -> runne_api::RuntimeSessionBinding {
    let initial = binding();
    runne_api::RuntimeSessionBinding::new(
        initial.stable().clone(),
        initial.ephemeral().daemon_instance_id(),
        initial.ephemeral().launch_generation(),
        *initial.ephemeral().session_id(),
        epoch,
        initial.ephemeral().sensitivity_ceiling(),
        *initial.certificate_sha256(),
    )
    .unwrap()
}

fn replay_state_with_epochs(
    binding: &runne_api::RuntimeSessionBinding,
    configured_epoch: i64,
    current_epoch: i64,
) -> ReplayHttpState {
    const RUNTIME_AUTHORITY: [u8; 16] = [0x44; 16];
    let connection =
        open_managed_connection(std::path::Path::new(":memory:"), ConnectionMode::Writer).unwrap();
    apply_migrations(&connection).unwrap();
    let generation = i64::try_from(binding.ephemeral().launch_generation()).unwrap();
    let service = ReplayService::new(
        Arc::new(ReplayStore::new(connection)),
        [11; 32],
        *binding.stable().lineage_id(),
        Arc::new(CurrentEpochAuthorization {
            epoch: current_epoch,
            authority: RUNTIME_AUTHORITY,
            generation,
        }),
    );
    ReplayHttpState::new(
        service,
        crate::replay::ReplayHttpBinding::new(RUNTIME_AUTHORITY, generation, configured_epoch)
            .unwrap(),
        crate::limits::LimitsConfig::default(),
        Arc::new(AvailableGuard),
    )
}

fn host_with_rotated_replay_epoch() -> (SecureLocalHttpHost, runne_api::RuntimeSessionBinding) {
    let binding = binding_at_epoch(1);
    let service = session_service(binding.clone());
    let host = SecureLocalHttpHost::new(
        VerifiedLocalTls::from_verified_listener(),
        HealthState {
            recovery_state: crate::health::RecoveryState::Ready,
        },
        AdmissionState::new(crate::health::RecoveryState::Ready),
        service,
        binding.clone(),
        false,
        clock(),
        profile_state_with_capabilities(CAPABILITIES),
        TaskRunHttpState::new(
            UnavailableTaskRunHost,
            ApiActor::new("runne-http-test").unwrap(),
        ),
        ConversationHttpState::new(
            UnavailableConversationHost,
            ApiActor::new("runne-http-test").unwrap(),
        ),
        replay_state_with_epochs(&binding, 0, 1),
    )
    .unwrap();
    (host, binding)
}
