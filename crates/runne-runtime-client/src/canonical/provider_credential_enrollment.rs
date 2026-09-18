use runne_api::{
    BeginProviderCredentialEnrollment, ProviderCredentialEnrollmentActionV2,
    ProviderCredentialOperationKindV2, ProviderCredentialOperationSnapshotV2,
    ProviderCredentialProviderV2, ProviderCredentialSafeSnapshotV2,
    ProviderCredentialVerificationKindV2, VerifyProviderCredential,
};

/// Capability required before protected credential enrollment is issued.
pub const PROVIDER_CREDENTIAL_ENROLLMENT_CAPABILITY_V2: &str =
    runne_api::PROVIDER_CREDENTIAL_ENROLLMENT_CAPABILITY_V2;

impl AuthenticatedRuntimeClient {
    /// Starts one protected, metadata-only credential enrollment operation.
    ///
    /// # Errors
    ///
    /// Returns `Incompatible` before transport unless this is an exact qualified
    /// protected profile. Credential material is never accepted by this method.
    pub async fn begin_credential_enrollment(
        &self,
        command: BeginProviderCredentialEnrollment,
    ) -> Result<ProviderCredentialOperationSnapshotV2, RuntimeApiError> {
        require_enrollment_capability(self)?;
        let provider = command.provider();
        let kind = match command.action() {
            ProviderCredentialEnrollmentActionV2::Pair => ProviderCredentialOperationKindV2::Pair,
            ProviderCredentialEnrollmentActionV2::Revoke => {
                ProviderCredentialOperationKindV2::Revoke
            }
            ProviderCredentialEnrollmentActionV2::MigrateLegacy => {
                ProviderCredentialOperationKindV2::MigrateLegacy
            }
        };
        let snapshot = self
            .send_enrollment_command("/v2/provider-credential-enrollment", &command, &[202])
            .await?;
        (snapshot.provider_id() == provider && snapshot.operation_kind() == kind)
            .then_some(snapshot)
            .ok_or_else(invalid_response)
    }

    /// Resumes one authenticated opaque credential enrollment operation.
    ///
    /// # Errors
    ///
    /// Returns `Incompatible` before transport unless the exact qualified
    /// protected capability profile was admitted.
    pub async fn resume_credential_enrollment(
        &self,
        operation_id: runne_api::ProviderCredentialOperationHandleV2,
    ) -> Result<ProviderCredentialOperationSnapshotV2, RuntimeApiError> {
        require_enrollment_capability(self)?;
        let snapshot = self
            .send_enrollment_command(
                "/v2/provider-credential-enrollment/resume",
                &EnrollmentResumeWire { operation_id },
                &[200],
            )
            .await?;
        (snapshot.operation_handle() == operation_id)
            .then_some(snapshot)
            .ok_or_else(invalid_response)
    }

    /// Fetches the current authenticated safe projection for one provider.
    ///
    /// # Errors
    ///
    /// Returns `Incompatible` before transport unless the exact qualified
    /// protected capability profile was admitted.
    pub async fn provider_credential_status(
        &self,
        provider: ProviderCredentialProviderV2,
    ) -> Result<ProviderCredentialSafeSnapshotV2, RuntimeApiError> {
        require_enrollment_capability(self)?;
        let response = self
            .authenticated_request(self.http_client().get(self.url(&format!(
                "/v2/providers/{}/credential-enrollment",
                provider_path(provider)
            ))))?
            .send()
            .await
            .map_err(map_transport)?;
        let snapshot =
            read_success_json::<ProviderCredentialSafeSnapshotV2>(response, &[200]).await?;
        (snapshot.provider_id() == provider)
            .then_some(snapshot)
            .ok_or_else(invalid_response)
    }

    /// Requests an explicit local or remote verification without material.
    ///
    /// # Errors
    ///
    /// Returns `Incompatible` before transport unless the exact qualified
    /// protected capability profile was admitted.
    pub async fn verify_provider_credential(
        &self,
        command: VerifyProviderCredential,
    ) -> Result<ProviderCredentialOperationSnapshotV2, RuntimeApiError> {
        require_enrollment_capability(self)?;
        let provider = command.provider();
        let kind = match command.verification_kind() {
            ProviderCredentialVerificationKindV2::Local => {
                ProviderCredentialOperationKindV2::VerifyLocal
            }
            ProviderCredentialVerificationKindV2::Remote => {
                ProviderCredentialOperationKindV2::VerifyRemote
            }
        };
        let snapshot = self
            .send_enrollment_command(
                "/v2/provider-credential-enrollment/verify",
                &command,
                &[202],
            )
            .await?;
        (snapshot.provider_id() == provider && snapshot.operation_kind() == kind)
            .then_some(snapshot)
            .ok_or_else(invalid_response)
    }

    async fn send_enrollment_command<T>(
        &self,
        path: &str,
        command: &T,
        expected_statuses: &[u16],
    ) -> Result<ProviderCredentialOperationSnapshotV2, RuntimeApiError>
    where
        T: serde::Serialize + Sync,
    {
        let body = serde_json::to_vec(command)
            .map_err(|_| RuntimeApiError::new(RuntimeApiErrorKind::InvalidRequest))?;
        let response = self
            .authenticated_request(self.http_client().post(self.url(path)))?
            .header(CONTENT_TYPE, "application/json")
            .body(body)
            .send()
            .await
            .map_err(map_transport)?;
        read_success_json(response, expected_statuses).await
    }
}

const fn provider_path(provider: ProviderCredentialProviderV2) -> &'static str {
    provider.as_str()
}

fn require_enrollment_capability(
    client: &AuthenticatedRuntimeClient,
) -> Result<(), RuntimeApiError> {
    (client.transport_kind() == RuntimeTransportKind::ProtectedBundled
        && is_enrollment_qualified_capability_profile(&client.session_info().capabilities))
    .then_some(())
    .ok_or_else(|| RuntimeApiError::new(RuntimeApiErrorKind::Incompatible))
}
