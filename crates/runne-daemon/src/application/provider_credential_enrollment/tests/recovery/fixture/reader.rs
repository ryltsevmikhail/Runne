use runne_api::ProviderCredentialEnrollmentHostError;
use runne_provider::{
    BindCredentialReadback, CredentialOperationAction, CredentialOperationSnapshot,
    CredentialReadbackDisposition,
};

use super::{FailurePoint, Fixture, digest};

pub struct StatefulReader<'a> {
    fixture: &'a Fixture,
}

impl<'a> StatefulReader<'a> {
    pub const fn new(fixture: &'a Fixture) -> Self {
        Self { fixture }
    }
}

impl super::super::super::super::CredentialEnrollmentReadback for StatefulReader<'_> {
    fn observe(
        &self,
        operation: &CredentialOperationSnapshot,
        command: &runne_provider::CredentialBrokerCommand,
    ) -> Result<BindCredentialReadback, ProviderCredentialEnrollmentHostError> {
        self.fixture.event("readback");
        if self.fixture.failure() == FailurePoint::Readback {
            return Err(ProviderCredentialEnrollmentHostError::Unavailable);
        }
        if !matches!(
            operation.action(),
            CredentialOperationAction::RetiredVersionCleanup
                | CredentialOperationAction::LegacySourceCleanup
        ) || command.operation_id() != operation.operation_id()
        {
            return Err(ProviderCredentialEnrollmentHostError::InvariantViolation);
        }
        BindCredentialReadback::new(
            operation.operation_id(),
            CredentialReadbackDisposition::ExactAbsence,
            digest(8),
        )
        .map_err(|_| ProviderCredentialEnrollmentHostError::InvariantViolation)
    }
}
