use super::{CredentialEnrollmentMeasurementAuthority, CredentialEnrollmentStoreAuthority};
use crate::{
    CredentialEnrollmentError, CredentialOperationId, MeasuredQualificationAdmission,
    ProviderQualificationAdmissionFence, QualificationSessionBinding,
};
use runne_native_qualification::{QualificationProcessRole, VerifiedQualificationFenceFacts};

impl CredentialEnrollmentMeasurementAuthority {
    /// Consumes combined signature-verified facts into this pair's exact measured admission.
    pub fn measure_qualification_admission(
        &self,
        facts: VerifiedQualificationFenceFacts,
        binding: QualificationSessionBinding,
        operation: CredentialOperationId,
        verified_at_unix_seconds: u64,
    ) -> Result<MeasuredQualificationAdmission, CredentialEnrollmentError> {
        let seconds =
            |value| i64::try_from(value).map_err(|_| CredentialEnrollmentError::InvalidInput);
        let role = match facts.process_role() {
            QualificationProcessRole::Desktop => "desktop",
            QualificationProcessRole::Writer => "writer",
            QualificationProcessRole::Runtime => "runtime",
            QualificationProcessRole::Service => "service",
        };
        let metadata = ProviderQualificationAdmissionFence::new(
            operation,
            facts.context_id(),
            facts.context_nonce(),
            facts.ticket_id(),
            facts.ticket_nonce(),
            facts.ticket_sha256(),
            facts.scenario().as_str(),
            facts.selector().as_str(),
            role,
            facts.candidate_sha256(),
            facts.raw_v3_tuple_sha256(),
            facts.source_revision(),
            facts.workflow_run_id(),
            facts.namespace_sha256(),
            seconds(facts.context_issued_at())?,
            seconds(facts.context_expires_at())?,
            seconds(facts.ticket_issued_at())?,
            seconds(facts.ticket_expires_at())?,
            binding.protected_session,
            binding.runtime_authority,
            binding.database_generation,
            binding.launch_generation,
            binding.supervisor_generation,
            seconds(verified_at_unix_seconds)?,
        )?;
        Ok(MeasuredQualificationAdmission {
            seal: self.seal.clone(),
            metadata,
            continuation: binding.continuation,
            fingerprint: facts.fingerprint(),
        })
    }

    /// Rejects a receipt from any foreign enrollment authority pair.
    pub fn validate_qualification_receipt(
        &self,
        receipt: &crate::ProviderQualificationAdmissionFenceReceipt,
    ) -> Result<(), CredentialEnrollmentError> {
        if receipt.belongs_to(&self.seal) {
            Ok(())
        } else {
            Err(CredentialEnrollmentError::InvalidEvidence)
        }
    }

    #[cfg(test)]
    pub(crate) fn test_only_measure_qualification(
        &self,
        metadata: ProviderQualificationAdmissionFence,
        continuation: crate::CredentialBindingDigest,
        fingerprint: [u8; 32],
    ) -> MeasuredQualificationAdmission {
        MeasuredQualificationAdmission {
            seal: self.seal.clone(),
            metadata,
            continuation,
            fingerprint,
        }
    }
}

impl CredentialEnrollmentStoreAuthority {
    /// Mints only after the trusted store commits the exact request and issued attempt.
    /// This capability authenticates inputs; SQLite commit ordering belongs to the store.
    pub fn issue_committed_qualification_receipt(
        &self,
        admission: MeasuredQualificationAdmission,
        issued: &crate::IssuedCredentialTicketAttempt,
    ) -> Result<crate::ProviderQualificationAdmissionFenceReceipt, CredentialEnrollmentError> {
        crate::ProviderQualificationAdmissionFenceReceipt::committed(
            self.seal.clone(),
            admission,
            issued,
        )
    }

    /// Verifies the request belongs to this store's paired measurement authority.
    pub fn validate_measured_qualification(
        &self,
        admission: &MeasuredQualificationAdmission,
    ) -> Result<(), CredentialEnrollmentError> {
        if admission.belongs_to(&self.seal) {
            Ok(())
        } else {
            Err(CredentialEnrollmentError::InvalidEvidence)
        }
    }
}
