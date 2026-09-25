use super::Fixture;
use runne_provider::{CompleteCredentialOperation, CredentialCompletionReceipt};

impl Fixture {
    pub(super) fn receipt_for(
        &self,
        input: &CompleteCredentialOperation,
    ) -> CredentialCompletionReceipt {
        let operation = self.operation.lock().unwrap();
        self.authority
            .hydrate_persisted_credential_completion_receipt(
                operation.operation_id(),
                operation.installation_owner_id(),
                operation.provider().clone(),
                operation.action(),
                operation
                    .allocated_credential_version()
                    .or(operation.target_credential_version())
                    .cloned(),
                operation.lifecycle_revision(),
                operation.fence(),
                operation.metadata().claimed_ticket_attempt().unwrap(),
                operation
                    .metadata()
                    .migration()
                    .map(|value| value.binding_digest()),
                operation
                    .metadata()
                    .qualified_release_tuple_digest()
                    .unwrap(),
                input.readback().disposition(),
                input.readback().observation_digest(),
                input
                    .readiness_observation()
                    .map(runne_provider::CredentialReadinessObservation::observation_id),
                self.successor.clone(),
            )
    }
}
