#![cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "Task 8 mounts this host only after authenticated protected admission is composed"
    )
)]

use std::sync::Arc;

use runne_api::{
    BeginProviderCredentialEnrollment, ProviderCredentialBaseRequestAuthority,
    ProviderCredentialCommandContext, ProviderCredentialEnrollmentHostError,
    ProviderCredentialEnrollmentHostPort, ProviderCredentialHostFuture,
    ProviderCredentialIntentConsumptionProof, ProviderCredentialOperationHandleV2,
    ProviderCredentialOperationSnapshotV2, ProviderCredentialProviderV2,
    ProviderCredentialStatusFuture, VerifyProviderCredential,
};
use runne_provider::{
    CredentialEnrollmentMeasurementAuthority, CredentialEnrollmentStoreAuthority,
    ProviderCredentialEnrollmentStore,
};

use super::{
    CredentialEnrollmentReadback, ProviderCredentialAdmission, ProviderCredentialEnrollmentStatus,
    begin::ProviderCredentialEnrollmentBegin, broker::pending::PendingBrokerRendezvousRegistry,
    operation_handle::ProviderCredentialOperationHandleIssuer,
    resume::ProviderCredentialEnrollmentResume,
};

/// Explicit verification owner supplied by Task 12's material-isolated boundary.
pub(crate) trait ProviderCredentialVerificationHost: Send + Sync {
    fn verify(
        &self,
        authority: ProviderCredentialBaseRequestAuthority,
        proof: ProviderCredentialIntentConsumptionProof,
        context: ProviderCredentialCommandContext,
        command: VerifyProviderCredential,
    ) -> Result<ProviderCredentialOperationSnapshotV2, ProviderCredentialEnrollmentHostError>;
}

/// Protected host composition with one recovery clock and no credential material.
pub(crate) struct DaemonProviderCredentialEnrollmentHost<'a, S: ?Sized, R: ?Sized, V> {
    begin: ProviderCredentialEnrollmentBegin<'a, S, R>,
    resume: ProviderCredentialEnrollmentResume<'a, S, R>,
    status: ProviderCredentialEnrollmentStatus<'a, S, R>,
    verification: V,
    now_high_water: Arc<dyn Fn() -> i64 + Send + Sync>,
}

impl<'a, S: ?Sized, R: ?Sized, V> DaemonProviderCredentialEnrollmentHost<'a, S, R, V> {
    /// Separates credential material handling into the supplied verification boundary.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        verifier: runne_api::ProviderCredentialRequestAuthorityVerifier,
        measurements: CredentialEnrollmentMeasurementAuthority,
        legacy_import_authority: CredentialEnrollmentStoreAuthority,
        handles: ProviderCredentialOperationHandleIssuer,
        store: &'a S,
        reader: &'a R,
        verification: V,
        now_high_water: Arc<dyn Fn() -> i64 + Send + Sync>,
    ) -> Self {
        let rendezvous = PendingBrokerRendezvousRegistry::new(handles.duplicate());
        Self {
            begin: ProviderCredentialEnrollmentBegin::new(
                ProviderCredentialAdmission::with_legacy_import_authority(
                    verifier.clone(),
                    measurements.clone(),
                    legacy_import_authority,
                ),
                handles.duplicate(),
                store,
                reader,
                rendezvous.clone(),
            ),
            resume: ProviderCredentialEnrollmentResume::new(
                ProviderCredentialAdmission::new(verifier.clone(), measurements.clone()),
                handles,
                store,
                reader,
                rendezvous,
            ),
            status: ProviderCredentialEnrollmentStatus::new(
                ProviderCredentialAdmission::new(verifier, measurements),
                store,
                reader,
            ),
            verification,
            now_high_water,
        }
    }
}

impl<S, R, V> ProviderCredentialEnrollmentHostPort
    for DaemonProviderCredentialEnrollmentHost<'_, S, R, V>
where
    S: ProviderCredentialEnrollmentStore + Send + Sync + ?Sized,
    R: CredentialEnrollmentReadback + Send + Sync + ?Sized,
    V: ProviderCredentialVerificationHost,
{
    fn begin<'b>(
        &'b self,
        authority: ProviderCredentialBaseRequestAuthority,
        proof: ProviderCredentialIntentConsumptionProof,
        context: ProviderCredentialCommandContext,
        command: BeginProviderCredentialEnrollment,
    ) -> ProviderCredentialHostFuture<'b> {
        Box::pin(async move {
            self.begin.admit(
                &authority,
                &proof,
                &context,
                &command,
                (self.now_high_water)(),
            )
        })
    }

    fn resume<'b>(
        &'b self,
        authority: ProviderCredentialBaseRequestAuthority,
        _context: ProviderCredentialCommandContext,
        operation_handle: ProviderCredentialOperationHandleV2,
    ) -> ProviderCredentialHostFuture<'b> {
        Box::pin(async move {
            self.resume
                .load(&authority, operation_handle, (self.now_high_water)())
        })
    }

    fn status<'b>(
        &'b self,
        authority: ProviderCredentialBaseRequestAuthority,
        provider: ProviderCredentialProviderV2,
    ) -> ProviderCredentialStatusFuture<'b> {
        Box::pin(async move {
            self.status
                .load(&authority, provider, (self.now_high_water)())
        })
    }

    fn verify<'b>(
        &'b self,
        authority: ProviderCredentialBaseRequestAuthority,
        proof: ProviderCredentialIntentConsumptionProof,
        context: ProviderCredentialCommandContext,
        command: VerifyProviderCredential,
    ) -> ProviderCredentialHostFuture<'b> {
        Box::pin(async move { self.verification.verify(authority, proof, context, command) })
    }
}
