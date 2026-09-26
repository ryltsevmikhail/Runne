use super::{
    Arc, Mutex, NativeRegistration, PreparedProtectedCredentialEnrollment,
    ProtectedBundledRuntimeError, ProtectedBundledRuntimeSupervisor, Stage, receive_phase,
    validate,
};

impl ProtectedBundledRuntimeSupervisor {
    /// Receives Revoke and `MigrateLegacy` terminal evidence without a secret-relay
    /// acknowledgement. Caller retains exclusive leases and non-cancellable writer
    /// cleanup ownership.
    ///
    /// # Errors
    /// Rejects Pair, consumed enrollment, changed launch or invalid terminal evidence.
    pub async fn finish_control_only_credential_enrollment_with_rejoin(
        supervisor: Arc<Mutex<Self>>,
        enrollment: PreparedProtectedCredentialEnrollment,
    ) -> Result<PreparedProtectedCredentialEnrollment, ProtectedBundledRuntimeError> {
        receive(supervisor, enrollment, NativeRegistration).await
    }
}

pub(super) async fn receive<R: super::RejoinRegistration>(
    supervisor: Arc<Mutex<ProtectedBundledRuntimeSupervisor>>,
    enrollment: PreparedProtectedCredentialEnrollment,
    registration: R,
) -> Result<PreparedProtectedCredentialEnrollment, ProtectedBundledRuntimeError> {
    if !matches!(
        enrollment.snapshot.operation_kind(),
        runne_api::ProviderCredentialOperationKindV2::Revoke
            | runne_api::ProviderCredentialOperationKindV2::MigrateLegacy
    ) || enrollment.relay.is_some()
        || enrollment.relay_taken
        || enrollment.terminal
    {
        return Err(ProtectedBundledRuntimeError::InvalidState);
    }
    let bootstrap = {
        let guard = supervisor
            .lock()
            .map_err(|_| ProtectedBundledRuntimeError::InvalidState)?;
        let bootstrap = guard
            .process
            .as_ref()
            .ok_or(ProtectedBundledRuntimeError::InvalidState)?
            .recovery_bootstrap()?;
        validate(&guard, &bootstrap)?;
        drop(guard);
        bootstrap
    };
    receive_phase(
        supervisor,
        enrollment,
        bootstrap,
        Stage::ControlOnlyTerminal,
        registration,
    )
    .await
}

#[cfg(all(test, feature = "test-support"))]
mod tests {
    use super::super::{ProviderCredentialOperationStateV2, read_frame, write_frame};
    use super::*;
    use crate::protected_runtime::credential_discovery::{prepare, reap};
    use runne_api::{
        ProviderCredentialOperationKindV2 as Kind,
        ProviderCredentialOperationSnapshotV2 as Snapshot,
        ProviderCredentialProviderV2 as Provider,
    };

    fn snapshot(
        kind: Kind,
        provider: Provider,
        state: ProviderCredentialOperationStateV2,
    ) -> Snapshot {
        Snapshot::new(
            runne_api::ProviderCredentialOperationHandleV2::from_bytes([1; 48]).unwrap(),
            None,
            provider,
            kind,
            state,
            1,
            1,
            false,
            None,
        )
        .unwrap()
    }

    #[tokio::test]
    async fn revoke_reads_sequence_two_terminal_without_relay_ack() {
        for provider in [Provider::OpenAi, Provider::DeepSeek] {
            let other_provider = match provider {
                Provider::OpenAi => Provider::DeepSeek,
                _ => Provider::OpenAi,
            };
            for (kind, consumed, sequence, terminal_kind, terminal_provider, accepted) in [
                (Kind::Revoke, false, 2, Kind::Revoke, provider, true),
                (
                    Kind::MigrateLegacy,
                    false,
                    2,
                    Kind::MigrateLegacy,
                    provider,
                    true,
                ),
                (Kind::Pair, false, 2, Kind::Revoke, provider, false),
                (Kind::Pair, false, 2, Kind::MigrateLegacy, provider, false),
                (Kind::MigrateLegacy, false, 2, Kind::Revoke, provider, false),
                (Kind::Revoke, true, 2, Kind::Revoke, provider, false),
                (Kind::Revoke, false, 1, Kind::Revoke, provider, false),
                (Kind::Revoke, false, 2, Kind::Pair, provider, false),
                (Kind::Revoke, false, 2, Kind::Revoke, other_provider, false),
            ] {
                let fixture = crate::protected_runtime::test_only_ready_v3_enrollment_supervisor();
                let (desktop, mut peer) = std::os::unix::net::UnixStream::pair().unwrap();
                peer.set_read_timeout(Some(std::time::Duration::from_millis(100)))
                    .unwrap();
                let (supervisor, _) = prepare(fixture, desktop, false).unwrap();
                let keys = runne_api::LaunchSecret::from_bytes([3; 32])
                    .unwrap()
                    .derive_keys();
                let codec =
                runne_api::ProtectedCredentialEnrollmentLifecycleCodec::from_protected_activation(
                    &keys,
                );
                write_frame(
                    &mut peer,
                    &codec
                        .encode_daemon_snapshot(
                            &snapshot(
                                terminal_kind,
                                terminal_provider,
                                ProviderCredentialOperationStateV2::Completed,
                            ),
                            sequence,
                        )
                        .unwrap(),
                )
                .unwrap();
                let enrollment = PreparedProtectedCredentialEnrollment {
                    codec,
                    snapshot: snapshot(
                        kind,
                        provider,
                        ProviderCredentialOperationStateV2::Prepared,
                    ),
                    relay: None,
                    relay_taken: consumed,
                    #[cfg(target_os = "linux")]
                    relay_fd_taken: false,
                    #[cfg(target_os = "linux")]
                    relay_lifecycle_frame: None,
                    terminal: false,
                };
                let result = ProtectedBundledRuntimeSupervisor::finish_control_only_credential_enrollment_with_rejoin(
            Arc::clone(&supervisor), enrollment,
        ).await;
                let unexpected_ack = read_frame(&mut peer);
                reap(&supervisor);
                assert_eq!(result.is_ok(), accepted);
                if let Ok(enrollment) = result {
                    assert!(enrollment.terminal());
                }
                assert!(unexpected_ack.is_err());
            }
        }
    }
}
