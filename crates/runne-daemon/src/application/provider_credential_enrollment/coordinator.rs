use super::{ProviderCredentialEffectAuthority, effect_authority::map_store};
use rand::{RngCore, rngs::OsRng};
use runne_api::{
    BeginProviderCredentialEnrollment, ProviderCredentialBaseRequestAuthority,
    ProviderCredentialBeginIntentBinding, ProviderCredentialCommandContext,
    ProviderCredentialEnrollmentHostError, ProviderCredentialIntentConsumptionProof,
    ProviderCredentialRequestAuthorityVerifier, ProviderCredentialVerifyIntentBinding,
    VerifyProviderCredential,
};
use runne_provider::{
    BeginCredentialOperation, BeginCredentialOperationOutcome, CredentialBindingDigest,
    CredentialEnrollmentMeasurementAuthority, CredentialInstallationOwnerId,
    CredentialLifecycleSnapshot, CredentialOperationAction, CredentialOperationId,
    CredentialVersionRef, ProviderCredentialEnrollmentStore, ProviderId,
};

#[allow(dead_code)]
pub(super) enum ProviderCredentialBeginAdmission {
    FreshWinner(ProviderCredentialEffectAuthority),
    ExactReplay(runne_provider::CredentialOperationSnapshot),
}

/// Coordinator-owned protected-request gate that precedes lifecycle access.
pub(crate) struct ProviderCredentialAdmission {
    verifier: ProviderCredentialRequestAuthorityVerifier,
    measurements: CredentialEnrollmentMeasurementAuthority,
}

impl ProviderCredentialAdmission {
    /// Retains the verifier paired with the only protected transport issuer.
    #[allow(dead_code)]
    pub(super) const fn new(
        verifier: ProviderCredentialRequestAuthorityVerifier,
        measurements: CredentialEnrollmentMeasurementAuthority,
    ) -> Self {
        Self {
            verifier,
            measurements,
        }
    }

    /// Rejects foreign authenticated-looking values before any downstream parsing.
    pub(super) fn require_base(
        &self,
        authority: &ProviderCredentialBaseRequestAuthority,
    ) -> Result<(), ProviderCredentialEnrollmentHostError> {
        self.verifier.verify_base(authority)
    }

    /// Rejects proofs not issued by the paired protected transport boundary.
    pub(super) fn require_intent(
        &self,
        proof: &ProviderCredentialIntentConsumptionProof,
    ) -> Result<(), ProviderCredentialEnrollmentHostError> {
        self.verifier.verify_intent_proof(proof)
    }

    /// Admits a begin proof only for the exact authenticated protected session.
    pub(super) fn require_begin(
        &self,
        authority: &ProviderCredentialBaseRequestAuthority,
        proof: &ProviderCredentialIntentConsumptionProof,
    ) -> Result<(), ProviderCredentialEnrollmentHostError> {
        self.require_base(authority)?;
        self.require_intent(proof)?;
        if proof.protected_session_binding() != authority.protected_session_id() {
            return Err(ProviderCredentialEnrollmentHostError::AccessDenied);
        }
        Ok(())
    }

    /// Binds the accepted proof to the exact public begin command and replay context.
    pub(super) fn require_begin_command(
        &self,
        authority: &ProviderCredentialBaseRequestAuthority,
        proof: &ProviderCredentialIntentConsumptionProof,
        command: &BeginProviderCredentialEnrollment,
        context: &ProviderCredentialCommandContext,
    ) -> Result<(), ProviderCredentialEnrollmentHostError> {
        self.require_begin(authority, proof)?;
        let binding = ProviderCredentialBeginIntentBinding::new(command, context);
        if proof.action_provider_revision_binding() != binding.action_provider_revision_digest()
            || proof.command_identity_binding() != binding.command_identity_digest()
        {
            return Err(ProviderCredentialEnrollmentHostError::AccessDenied);
        }
        Ok(())
    }

    /// Binds a verification proof to its exact provider, revision, kind, and command context.
    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "Task 6 admission is prepared before the protected verification host is composed"
        )
    )]
    pub(super) fn require_verify_command(
        &self,
        authority: &ProviderCredentialBaseRequestAuthority,
        proof: &ProviderCredentialIntentConsumptionProof,
        command: &VerifyProviderCredential,
        context: &ProviderCredentialCommandContext,
    ) -> Result<(), ProviderCredentialEnrollmentHostError> {
        self.require_begin(authority, proof)?;
        let binding = ProviderCredentialVerifyIntentBinding::new(command, context);
        if proof.action_provider_revision_binding() != binding.action_provider_revision_digest()
            || proof.command_identity_binding() != binding.command_identity_digest()
        {
            return Err(ProviderCredentialEnrollmentHostError::AccessDenied);
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    #[allow(dead_code)]
    pub(super) fn admit_begin<S: ProviderCredentialEnrollmentStore>(
        &self,
        authority: &ProviderCredentialBaseRequestAuthority,
        proof: &ProviderCredentialIntentConsumptionProof,
        command: &BeginProviderCredentialEnrollment,
        context: &ProviderCredentialCommandContext,
        snapshot: CredentialLifecycleSnapshot,
        store: &S,
    ) -> Result<ProviderCredentialBeginAdmission, ProviderCredentialEnrollmentHostError> {
        let input = self.begin_input(authority, proof, command, context, snapshot)?;
        match store.begin(input).map_err(map_store)? {
            BeginCredentialOperationOutcome::FreshWinner(operation) => {
                Ok(ProviderCredentialBeginAdmission::FreshWinner(
                    ProviderCredentialEffectAuthority::from_fresh_winner(operation),
                ))
            }
            BeginCredentialOperationOutcome::ExactReplay(operation) => {
                Ok(ProviderCredentialBeginAdmission::ExactReplay(operation))
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn begin_input(
        &self,
        authority: &ProviderCredentialBaseRequestAuthority,
        proof: &ProviderCredentialIntentConsumptionProof,
        command: &BeginProviderCredentialEnrollment,
        context: &ProviderCredentialCommandContext,
        snapshot: CredentialLifecycleSnapshot,
    ) -> Result<BeginCredentialOperation, ProviderCredentialEnrollmentHostError> {
        self.require_begin_command(authority, proof, command, context)?;
        let provider = provider(command.provider())?;
        if snapshot.provider() != &provider
            || snapshot.lifecycle_revision().get() != command.expected_lifecycle_revision()
        {
            return Err(ProviderCredentialEnrollmentHostError::Conflict);
        }
        let (action, allocated, target) = match command.action() {
            runne_api::ProviderCredentialEnrollmentActionV2::Pair => (
                CredentialOperationAction::Pair,
                Some(version(&provider, snapshot.next_credential_version())?),
                None,
            ),
            runne_api::ProviderCredentialEnrollmentActionV2::Revoke => (
                CredentialOperationAction::Revoke,
                None,
                snapshot.active_version().cloned(),
            ),
            runne_api::ProviderCredentialEnrollmentActionV2::MigrateLegacy => {
                return Err(ProviderCredentialEnrollmentHostError::Unsupported);
            }
        };
        let owner = CredentialInstallationOwnerId::from_bytes(*authority.installation_identity())
            .map_err(|_| ProviderCredentialEnrollmentHostError::AccessDenied)?;
        let digest = CredentialBindingDigest::from_measured(*proof.proof_digest())
            .map_err(|_| ProviderCredentialEnrollmentHostError::AccessDenied)?;
        let manifest = self
            .measurements
            .release_manifest_digest(*authority.release_tuple_digest())
            .map_err(|_| ProviderCredentialEnrollmentHostError::AccessDenied)?;
        let tuple = self
            .measurements
            .issue_qualified_credential_release_tuple(manifest)
            .map_err(|_| ProviderCredentialEnrollmentHostError::AccessDenied)?;
        let operation_id = allocate_operation_id()?;
        BeginCredentialOperation::new(
            context.command_id,
            context.idempotency_key.clone(),
            operation_id,
            owner,
            provider,
            action,
            allocated,
            target,
            snapshot.lifecycle_revision(),
            snapshot.fence(),
            digest,
            u64::try_from(proof.expires_at_high_water())
                .map_err(|_| ProviderCredentialEnrollmentHostError::AccessDenied)?,
        )
        .map(|input| input.with_qualified_release_tuple(tuple))
        .map_err(|_| ProviderCredentialEnrollmentHostError::AccessDenied)
    }
}

fn allocate_operation_id() -> Result<CredentialOperationId, ProviderCredentialEnrollmentHostError> {
    let mut bytes = [0_u8; 16];
    OsRng
        .try_fill_bytes(&mut bytes)
        .map_err(|_| ProviderCredentialEnrollmentHostError::Unavailable)?;
    CredentialOperationId::from_bytes(bytes)
        .map_err(|_| ProviderCredentialEnrollmentHostError::Unavailable)
}

fn provider(
    value: runne_api::ProviderCredentialProviderV2,
) -> Result<ProviderId, ProviderCredentialEnrollmentHostError> {
    ProviderId::new(match value {
        runne_api::ProviderCredentialProviderV2::OpenAi => "openai",
        runne_api::ProviderCredentialProviderV2::DeepSeek => "deepseek",
    })
    .map_err(|_| ProviderCredentialEnrollmentHostError::InvalidRequest)
}

fn version(
    provider: &ProviderId,
    next: u64,
) -> Result<CredentialVersionRef, ProviderCredentialEnrollmentHostError> {
    CredentialVersionRef::new(provider.clone(), next)
        .map_err(|_| ProviderCredentialEnrollmentHostError::InvariantViolation)
}
