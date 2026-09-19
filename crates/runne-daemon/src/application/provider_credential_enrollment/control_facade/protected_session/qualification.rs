use super::DaemonProtectedCredentialEnrollmentSession;
use crate::application::provider_credential_enrollment::broker::{
    ProviderCredentialBroker, QualifiedIssuedTicket,
};
use crate::protected_activation::control_v3::initial_exchange::VerifiedQualificationAdmission;
use runne_api::ProviderCredentialEnrollmentHostError;
use runne_provider::{
    CredentialBindingDigest, ProviderQualificationAdmissionFenceReceipt,
    QualificationSessionBinding,
};
use std::sync::Arc;

#[cfg(test)]
mod atomic_tests;
#[cfg(test)]
mod connected_attestation;
#[cfg(test)]
mod connected_release_fixture;
#[cfg(test)]
mod connected_test_support;
#[cfg(test)]
mod connected_tests;
#[cfg(test)]
mod tests;

struct CommittedQualification {
    admission: VerifiedQualificationAdmission,
    receipt: ProviderQualificationAdmissionFenceReceipt,
    qualified: QualifiedIssuedTicket,
    fingerprint: [u8; 32],
    continuation: CredentialBindingDigest,
}

/// Private witness minted only after the durable receipt binds this session's fence.
pub(crate) struct PostcommitAdmissionPermit(());

impl PostcommitAdmissionPermit {
    const fn after_fence_validation() -> Self {
        Self(())
    }
}

impl DaemonProtectedCredentialEnrollmentSession {
    /// Moves the initially verified pair into a fresh session exactly once.
    /// No failure path can remove this carrier and resume ordinary issuance.
    pub(crate) fn retain_qualification(
        mut self,
        qualification: VerifiedQualificationAdmission,
    ) -> Result<Self, ProviderCredentialEnrollmentHostError> {
        if self.qualification.is_some()
            || self.qualification_snapshot.is_some()
            || self.pending.is_some()
            || self.begun.is_some()
            || self.verified.is_some()
            || self.recovery.started
        {
            return Err(ProviderCredentialEnrollmentHostError::AccessDenied);
        }
        let retained = super::ProtectedEnrollmentSessionFacts::from_owned(
            qualification.retained_owned(),
            self.control.runtime_authority,
            self.control.database_generation,
        )?;
        if retained != self.facts {
            return Err(ProviderCredentialEnrollmentHostError::AccessDenied);
        }
        self.qualification_snapshot = Some(retained);
        self.qualification = Some(qualification);
        Ok(self)
    }

    fn qualification_snapshot_matches(
        &self,
        current: &runne_api::ProtectedCredentialEnrollmentOwnedLaunchV3,
    ) -> Result<(), ProviderCredentialEnrollmentHostError> {
        let live = super::ProtectedEnrollmentSessionFacts::from_owned(
            current,
            self.control.runtime_authority,
            self.control.database_generation,
        )?;
        if self.qualification_snapshot.as_ref() != Some(&live) || live != self.facts {
            return Err(ProviderCredentialEnrollmentHostError::AccessDenied);
        }
        Ok(())
    }

    /// Called under the live session rotation lock, before ordinary ticket selection/send.
    pub(crate) fn fence_qualification_before_delivery(
        &mut self,
        current: &runne_api::ProtectedCredentialEnrollmentOwnedLaunchV3,
        installed: &runne_platform_desktop::VerifiedInstalledEnrollmentMeasurementFacts,
        continuation: CredentialBindingDigest,
    ) -> Result<(), ProviderCredentialEnrollmentHostError> {
        if self.qualification_snapshot.is_none() {
            return Ok(());
        }
        let mut verifier =
            runne_native_qualification::QualificationAdmissionVerifier::from_compiled_policy();
        let committed = self.commit_qualification(
            current,
            installed,
            continuation,
            &mut verifier,
            unix_seconds()?,
        )?;
        self.accept_qualification_fence(committed, current, unix_seconds()?)?;
        Ok(())
    }

    fn commit_qualification(
        &mut self,
        current: &runne_api::ProtectedCredentialEnrollmentOwnedLaunchV3,
        installed: &runne_platform_desktop::VerifiedInstalledEnrollmentMeasurementFacts,
        continuation: CredentialBindingDigest,
        verifier: &mut runne_native_qualification::QualificationAdmissionVerifier,
        now: u64,
    ) -> Result<CommittedQualification, ProviderCredentialEnrollmentHostError> {
        self.qualification_snapshot_matches(current)?;
        if self.recovery.started || self.qualification_fenced.is_some() {
            return Err(ProviderCredentialEnrollmentHostError::AccessDenied);
        }
        let operation = self.operation_id()?;
        let admission = self
            .qualification
            .take()
            .ok_or(ProviderCredentialEnrollmentHostError::AccessDenied)?;
        // Snapshot remains set on every error: taking this Option cannot select ordinary issuance.
        let facts = admission.reverify_for_fence(installed, current, verifier, now)?;
        let fingerprint = facts.fingerprint();
        if facts.process_role() != runne_native_qualification::QualificationProcessRole::Writer
            || facts.selector()
                != runne_native_qualification::QualificationFaultSelector::WriterProcess
        {
            return Err(ProviderCredentialEnrollmentHostError::AccessDenied);
        }
        let binding = QualificationSessionBinding {
            protected_session: CredentialBindingDigest::from_measured(super::session_binding(
                &self.facts,
            ))
            .map_err(|_| ProviderCredentialEnrollmentHostError::AccessDenied)?,
            continuation,
            runtime_authority: self.facts.runtime_authority,
            database_generation: self.facts.database_generation,
            launch_generation: self.facts.launch_generation,
            supervisor_generation: self.facts.supervisor_generation,
        };
        let measured = self
            .control
            .measurements
            .measure_qualification_admission(facts, binding, operation, now)
            .map_err(|_| ProviderCredentialEnrollmentHostError::AccessDenied)?;
        let broker = ProviderCredentialBroker::new(Arc::new(self.control.measurements.clone()));
        let (qualified, receipt) =
            broker.issue_qualified_ticket(measured, self.control.store.as_ref())?;
        Ok(CommittedQualification {
            admission,
            receipt,
            qualified,
            fingerprint,
            continuation,
        })
    }

    fn accept_qualification_fence(
        &mut self,
        committed: CommittedQualification,
        current: &runne_api::ProtectedCredentialEnrollmentOwnedLaunchV3,
        now: u64,
    ) -> Result<(), ProviderCredentialEnrollmentHostError> {
        self.qualification_snapshot_matches(current)?;
        let receipt = &committed.receipt;
        let broker = ProviderCredentialBroker::new(Arc::new(self.control.measurements.clone()));
        broker.validate_qualification_receipt(receipt)?;
        let now =
            i64::try_from(now).map_err(|_| ProviderCredentialEnrollmentHostError::AccessDenied)?;
        if self.qualification_fenced.is_some()
            || committed.admission.retained_owned() != current
            || receipt.fingerprint() != committed.fingerprint
            || receipt.operation_id() != self.operation_id()?
            || receipt.operation_id() != committed.qualified.receipt().operation().operation_id()
            || receipt.ticket_attempt() != committed.qualified.receipt().ticket_attempt()
            || receipt.committed_at() != committed.qualified.receipt().issued_at_high_water()
            || receipt.continuation_binding_digest() != committed.continuation
            || receipt.protected_session_digest().as_bytes() != super::session_binding(&self.facts)
            || receipt.runtime_authority_id() != self.facts.runtime_authority
            || receipt.database_generation() != self.facts.database_generation
            || receipt.launch_generation() != self.facts.launch_generation
            || receipt.supervisor_generation() != self.facts.supervisor_generation
            || now < receipt.committed_at()
            || now >= receipt.effective_expires_at()
            || now >= committed.qualified.receipt().expires_at_high_water()
        {
            return Err(ProviderCredentialEnrollmentHostError::AccessDenied);
        }
        self.qualification_fenced = Some(FencedQualificationAdmission {
            postcommit: committed.admission.into_postcommit(
                committed.qualified,
                PostcommitAdmissionPermit::after_fence_validation(),
            ),
            _receipt: committed.receipt,
        });
        Ok(())
    }
}

fn unix_seconds() -> Result<u64, ProviderCredentialEnrollmentHostError> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .map_err(|_| ProviderCredentialEnrollmentHostError::Unavailable)
}

/// Retains the exact original admission and committed receipt; delivery remains closed.
pub(super) struct FencedQualificationAdmission {
    postcommit: crate::protected_activation::control_v3::initial_exchange::qualification_fence::PostcommitQualificationAdmission,
    _receipt: ProviderQualificationAdmissionFenceReceipt,
}

pub(crate) struct FencedWriterDelivery {
    postcommit: crate::protected_activation::control_v3::initial_exchange::qualification_fence::PostcommitQualificationAdmission,
}

impl FencedQualificationAdmission {
    pub(crate) fn into_writer_delivery(
        self,
    ) -> Result<FencedWriterDelivery, ProviderCredentialEnrollmentHostError> {
        Ok(FencedWriterDelivery {
            postcommit: self.postcommit,
        })
    }
}

impl FencedWriterDelivery {
    pub(super) fn into_writer_exchange(
        self,
    ) -> Result<
        crate::application::provider_credential_enrollment::broker::FencedWriterExchange,
        ProviderCredentialEnrollmentHostError,
    > {
        self.postcommit
            .into_writer_exchange()
            .map_err(|_| ProviderCredentialEnrollmentHostError::AccessDenied)
    }
}
