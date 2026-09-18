use runne_application::provider::ProviderAdmissionError;
use runne_provider::{ProviderPort, ProviderPreEffectRejection};

use super::{ProviderCoordinatorOutcome, ProviderEffectPort, SqliteProviderDispatchCoordinator};

impl<'a, P, E> SqliteProviderDispatchCoordinator<'a, P, E>
where
    P: ProviderPort + ?Sized,
    E: ProviderEffectPort + ?Sized,
{
    pub(super) fn reject_before_effect(
        &self,
        attempt_id: runne_provider::DispatchAttemptId,
        fencing_token: u64,
        reason: ProviderPreEffectRejection,
    ) -> Result<ProviderCoordinatorOutcome, ProviderAdmissionError> {
        if self
            .dispatch_store
            .mark_rejected_before_effect(attempt_id, fencing_token, reason)
            .is_err()
        {
            let _ = self
                .dispatch_store
                .mark_uncertain(attempt_id, fencing_token);
            Ok(ProviderCoordinatorOutcome::Uncertain)
        } else {
            Ok(ProviderCoordinatorOutcome::RejectedBeforeEffect { reason })
        }
    }
}
