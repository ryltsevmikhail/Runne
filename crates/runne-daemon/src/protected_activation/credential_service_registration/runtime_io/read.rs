use runne_api::ProviderCredentialEnrollmentHostError;
use runne_platform_ports::credential_service::CredentialServiceRuntimePort;
use runne_provider::{
    CredentialBindingDigest, CredentialDispatchEffectReceiptAuthority, CredentialFence,
    CredentialLifecycleRevision, CredentialMaterial, CredentialRuntimeReadAuthority,
    CredentialRuntimeReadBinding, CredentialServiceCorrelation, CredentialServiceDeadline,
    CredentialServiceEpoch, CredentialServiceReply, CredentialServiceRequest,
    CredentialServiceRequestSequence, CredentialVersionRef,
};

use super::super::ServiceVersionMetadata;
use super::{CredentialServiceRuntimeSession, RuntimeCall};

impl CredentialServiceRuntimeSession {
    pub(in crate::protected_activation) fn read_metadata(
        &mut self,
        runtime: &tokio::runtime::Handle,
        authority: &CredentialRuntimeReadAuthority,
        version: CredentialVersionRef,
        lifecycle: CredentialLifecycleRevision,
        fence: CredentialFence,
        now_unix_millis: u64,
    ) -> Result<ServiceVersionMetadata, ProviderCredentialEnrollmentHostError> {
        let client = self
            .client
            .take()
            .ok_or(ProviderCredentialEnrollmentHostError::Unsupported)?;
        let result = runtime.block_on(self.read_metadata_with_port(
            &client,
            authority,
            version.clone(),
            lifecycle,
            fence,
            now_unix_millis,
        ));
        self.client = Some(client);
        if !should_reconnect_metadata(&result, self.last_transport_failure, self.missing_epoch) {
            return result;
        }
        let configuration = self
            .configuration
            .clone()
            .ok_or(ProviderCredentialEnrollmentHostError::Unavailable)?;
        let client =
            match runne_macos_xpc::CredentialServiceRuntimeXpcClient::connect(configuration) {
                Ok(client) => client,
                Err(_) => {
                    self.queue_transport_rejoin()?;
                    return Err(ProviderCredentialEnrollmentHostError::Unavailable);
                }
            };
        let result = runtime.block_on(self.read_metadata_with_port(
            &client,
            authority,
            version,
            lifecycle,
            fence,
            now_unix_millis,
        ));
        self.client = Some(client);
        if self.last_transport_failure {
            self.queue_transport_rejoin()?;
        }
        result
    }

    pub(in crate::protected_activation) async fn read_metadata_with_port<
        P: CredentialServiceRuntimePort,
    >(
        &mut self,
        port: &P,
        authority: &CredentialRuntimeReadAuthority,
        version: CredentialVersionRef,
        lifecycle: CredentialLifecycleRevision,
        fence: CredentialFence,
        now_unix_millis: u64,
    ) -> Result<ServiceVersionMetadata, ProviderCredentialEnrollmentHostError> {
        let (binding, lifetime) =
            self.read_binding(authority, version, lifecycle, fence, now_unix_millis)?;
        let request = authority
            .issue_metadata_readback(binding)
            .map_err(|_| ProviderCredentialEnrollmentHostError::InvariantViolation)?;
        match self
            .exchange(
                port,
                CredentialServiceRequest::MetadataReadback(request),
                lifetime,
                RuntimeCall::Metadata,
            )
            .await?
        {
            CredentialServiceReply::Metadata { present } => Ok(ServiceVersionMetadata {
                present,
                source_revision: None,
            }),
            CredentialServiceReply::LegacyMetadata { source_revision } => {
                Ok(ServiceVersionMetadata {
                    present: true,
                    source_revision: Some(
                        runne_secure_store::ProviderCredentialSourceRevision::new(source_revision)
                            .map_err(|_| ProviderCredentialEnrollmentHostError::AccessDenied)?,
                    ),
                })
            }
            CredentialServiceReply::Rejected(disposition) => Err(self.map_disposition(disposition)),
            _ => Err(ProviderCredentialEnrollmentHostError::AccessDenied),
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub(in crate::protected_activation) async fn read_material_with_port<
        P: CredentialServiceRuntimePort,
    >(
        &mut self,
        port: &P,
        authority: &CredentialRuntimeReadAuthority,
        receipts: &CredentialDispatchEffectReceiptAuthority,
        version: CredentialVersionRef,
        lifecycle: CredentialLifecycleRevision,
        fence: CredentialFence,
        receipt: CredentialBindingDigest,
        now_unix_millis: u64,
    ) -> Result<CredentialMaterial, ProviderCredentialEnrollmentHostError> {
        let (binding, lifetime) =
            self.read_binding(authority, version, lifecycle, fence, now_unix_millis)?;
        let request = receipts
            .issue_point_of_use_read(binding, receipt)
            .map_err(|_| ProviderCredentialEnrollmentHostError::InvariantViolation)?;
        match self
            .exchange(
                port,
                CredentialServiceRequest::PointOfUseRead(request),
                lifetime,
                RuntimeCall::Material,
            )
            .await?
        {
            CredentialServiceReply::Material(material) => Ok(material),
            CredentialServiceReply::Rejected(disposition) => Err(self.map_disposition(disposition)),
            _ => Err(ProviderCredentialEnrollmentHostError::AccessDenied),
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn read_material(
        &mut self,
        runtime: &tokio::runtime::Handle,
        authority: &CredentialRuntimeReadAuthority,
        receipts: &CredentialDispatchEffectReceiptAuthority,
        version: CredentialVersionRef,
        lifecycle: CredentialLifecycleRevision,
        fence: CredentialFence,
        receipt: CredentialBindingDigest,
        now_unix_millis: u64,
    ) -> Result<CredentialMaterial, ProviderCredentialEnrollmentHostError> {
        let client = self
            .client
            .take()
            .ok_or(ProviderCredentialEnrollmentHostError::Unsupported)?;
        let result = runtime.block_on(self.read_material_with_port(
            &client,
            authority,
            receipts,
            version,
            lifecycle,
            fence,
            receipt,
            now_unix_millis,
        ));
        self.client = Some(client);
        if self.last_transport_failure {
            self.queue_transport_rejoin()?;
        }
        result
    }

    fn read_binding(
        &mut self,
        authority: &CredentialRuntimeReadAuthority,
        version: CredentialVersionRef,
        lifecycle: CredentialLifecycleRevision,
        fence: CredentialFence,
        now_unix_millis: u64,
    ) -> Result<(CredentialRuntimeReadBinding, u64), ProviderCredentialEnrollmentHostError> {
        let sequence = self.next_sequence()?;
        let expires_at = self.expires_at(now_unix_millis)?;
        let binding = authority
            .issue_binding(
                CredentialServiceEpoch::from_bytes(*self.binding.service_epoch())
                    .map_err(|_| ProviderCredentialEnrollmentHostError::InvariantViolation)?,
                *self.binding.installation_owner(),
                *self.binding.protected_session_id(),
                self.binding.runtime_generation(),
                CredentialBindingDigest::from_measured(*self.binding.release_binding())
                    .map_err(|_| ProviderCredentialEnrollmentHostError::InvariantViolation)?,
                version.provider().clone(),
                version,
                lifecycle,
                fence,
                CredentialServiceRequestSequence::new(sequence)
                    .map_err(|_| ProviderCredentialEnrollmentHostError::InvariantViolation)?,
                CredentialServiceCorrelation::from_bytes(*uuid::Uuid::now_v7().as_bytes())
                    .map_err(|_| ProviderCredentialEnrollmentHostError::Unavailable)?,
                CredentialServiceDeadline::new(now_unix_millis, expires_at)
                    .map_err(|_| ProviderCredentialEnrollmentHostError::AccessDenied)?,
            )
            .map_err(|_| ProviderCredentialEnrollmentHostError::InvariantViolation)?;
        Ok((binding, expires_at - now_unix_millis))
    }

    pub(super) fn queue_transport_rejoin(
        &mut self,
    ) -> Result<(), ProviderCredentialEnrollmentHostError> {
        self.missing_epoch = Some(
            CredentialServiceEpoch::from_bytes(*self.binding.service_epoch())
                .map_err(|_| ProviderCredentialEnrollmentHostError::InvariantViolation)?,
        );
        Ok(())
    }
}

fn should_reconnect_metadata(
    result: &Result<ServiceVersionMetadata, ProviderCredentialEnrollmentHostError>,
    transport_failure: bool,
    missing_epoch: Option<CredentialServiceEpoch>,
) -> bool {
    matches!(
        result,
        Err(ProviderCredentialEnrollmentHostError::Unavailable)
    ) && transport_failure
        && missing_epoch.is_none()
}

#[cfg(test)]
mod policy_tests {
    use super::*;

    #[test]
    fn reconnects_only_unavailable_metadata_without_authenticated_session_loss() {
        let unavailable = Err(ProviderCredentialEnrollmentHostError::Unavailable);
        let denied = Err(ProviderCredentialEnrollmentHostError::AccessDenied);
        let epoch = CredentialServiceEpoch::from_bytes([3; 16]).unwrap();

        assert!(should_reconnect_metadata(&unavailable, true, None));
        assert!(!should_reconnect_metadata(&unavailable, true, Some(epoch)));
        assert!(!should_reconnect_metadata(&unavailable, false, None));
        assert!(!should_reconnect_metadata(&denied, true, None));
        assert!(!should_reconnect_metadata(
            &Ok(ServiceVersionMetadata {
                present: true,
                source_revision: None
            }),
            true,
            None
        ));
    }
}
