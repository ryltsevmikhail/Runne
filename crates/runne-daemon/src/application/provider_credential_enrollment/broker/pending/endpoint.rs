#![cfg_attr(
    not(any(
        test,
        all(
            target_os = "macos",
            target_arch = "aarch64",
            feature = "desktop-protected"
        )
    )),
    expect(
        dead_code,
        reason = "endpoint handoff is test-driven until the D1 Linux composition slice mounts it"
    )
)]

use super::*;

/// Move-only pending rendezvous removed before its current authority is validated.
pub(crate) struct PendingBrokerEndpointHandoff {
    pub(super) binding: PendingBrokerRendezvousBinding,
    // The witness belongs to the production handoff path; unit-test builds
    // never read it. Unconditional `allow` under `test` (not `expect`): on
    // platforms where a test does read it, an expectation would be
    // unfulfilled and break `-D warnings`.
    #[cfg_attr(test, allow(dead_code))]
    pub(super) authority_witness: ProviderCredentialBrokerHandoffWitness,
    #[cfg_attr(
        all(test, not(all(target_os = "macos", target_arch = "aarch64"))),
        expect(
            dead_code,
            reason = "portable recovery tests retain transfer authority for native handoff"
        )
    )]
    pub(super) broker_transfer: Option<ProviderCredentialBrokerTransferAuthority>,
    pub(super) rendezvous: DaemonOwnedUnixBrokerRendezvous,
}

/// Opaque daemon control authority awaiting separate writer peer/release admission.
#[cfg(all(feature = "desktop-protected", any(test, unix)))]
pub(crate) struct AwaitingVerifiedWriter {
    pub(in crate::application::provider_credential_enrollment::broker) binding:
        PendingBrokerRendezvousBinding,
    pub(in crate::application::provider_credential_enrollment::broker) authority:
        DaemonBrokerAuthority,
    pub(in crate::application::provider_credential_enrollment::broker) transfer_authority:
        ProviderCredentialBrokerTransferAuthority,
    pub(in crate::application::provider_credential_enrollment::broker) handoff:
        runne_platform_desktop::provider_credential_broker::VerifiedDaemonWriterEndpointHandoffFacts,
}

impl PendingBrokerRendezvousRegistry {
    /// Removes before validation so failures cannot retain or replay writer authority.
    pub(crate) fn begin_endpoint_handoff(
        &self,
        rendezvous_id: &str,
        operation: &CredentialOperationSnapshot,
        authority: &ProviderCredentialBaseRequestAuthority,
        proof: &ProviderCredentialIntentConsumptionProof,
        now_high_water: i64,
    ) -> Result<PendingBrokerEndpointHandoff, ProviderCredentialEnrollmentHostError> {
        let operation_id = self.handles.resolve_broker_rendezvous_id(rendezvous_id)?;
        let entry = self
            .entries
            .lock()
            .map_err(|_| ProviderCredentialEnrollmentHostError::Unavailable)?
            .remove(&operation_id)
            .ok_or(ProviderCredentialEnrollmentHostError::AccessDenied)?;
        if operation_id != operation.operation_id() {
            return Err(ProviderCredentialEnrollmentHostError::AccessDenied);
        }
        let current =
            PendingBrokerRendezvousBinding::new(operation, authority, proof, now_high_water)?;
        if entry.binding != current || !entry.authority_witness.matches_authority(authority) {
            return Err(ProviderCredentialEnrollmentHostError::AccessDenied);
        }
        Ok(PendingBrokerEndpointHandoff {
            binding: entry.binding,
            authority_witness: entry.authority_witness,
            broker_transfer: entry.broker_transfer,
            rendezvous: entry.rendezvous,
        })
    }
}

impl PendingBrokerEndpointHandoff {
    pub(crate) const fn operation_id(&self) -> CredentialOperationId {
        self.binding.operation_id
    }

    pub(crate) fn rendezvous_facts(&self) -> ([u8; 32], [u8; 32]) {
        (
            self.rendezvous.channel_binding(),
            self.rendezvous.publication_public_key(),
        )
    }

    #[cfg(test)]
    pub(crate) fn matches_safe_operation_for_test(
        &self,
        snapshot: &runne_api::ProviderCredentialOperationSnapshotV2,
        handles: &ProviderCredentialOperationHandleIssuer,
    ) -> bool {
        handles.resolve(snapshot.operation_handle()).ok() == Some(self.binding.operation_id)
    }
}

#[cfg(all(feature = "desktop-protected", any(test, unix)))]
impl PendingBrokerEndpointHandoff {
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    pub(crate) fn take_broker_transfer(
        &mut self,
    ) -> Option<ProviderCredentialBrokerTransferAuthority> {
        self.broker_transfer.take()
    }

    /// Sends the endpoint and keeps only opaque authority pending later native admission.
    pub(crate) fn send_endpoint(
        mut self,
        transport: std::os::unix::net::UnixStream,
        transfer_authority: ProviderCredentialBrokerTransferAuthority,
    ) -> Result<AwaitingVerifiedWriter, ProviderCredentialEnrollmentHostError> {
        if !transfer_authority
            .matches_handoff(&self.authority_witness, &self.binding.protected_session)
        {
            return Err(ProviderCredentialEnrollmentHostError::AccessDenied);
        }
        let handoff = self
            .rendezvous
            .handoff_writer_endpoint(transport, &transfer_authority)?;
        let authority = self.rendezvous.take_daemon_authority()?;
        Ok(AwaitingVerifiedWriter {
            binding: self.binding,
            authority,
            transfer_authority,
            handoff,
        })
    }
}
