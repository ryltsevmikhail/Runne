use runne_api::ProviderCredentialEnrollmentHostError;

use super::CredentialServiceRuntimeGateway;

impl CredentialServiceRuntimeGateway {
    pub(super) fn retry_metadata_after_rejoin<T>(
        &self,
        mut attempt: impl FnMut() -> (
            Result<T, ProviderCredentialEnrollmentHostError>,
            Option<runne_provider::CredentialServiceEpoch>,
        ),
    ) -> Result<T, ProviderCredentialEnrollmentHostError> {
        let (result, missing_epoch) = attempt();
        let Some(epoch) = missing_epoch else {
            return result;
        };
        let ticket = self.rejoin.queue(epoch)?;
        if !self.rejoin.wait(ticket, super::REJOIN_WAIT) {
            return Err(ProviderCredentialEnrollmentHostError::Unavailable);
        }
        attempt().0
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use runne_provider::{CredentialEnrollmentAuthorityPair, CredentialServiceEpoch};

    use super::*;

    #[tokio::test]
    async fn metadata_session_loss_retries_exactly_once_after_completed_rejoin() {
        let (store, _) = CredentialEnrollmentAuthorityPair::new().split();
        let gateway = Arc::new(CredentialServiceRuntimeGateway::new(
            store,
            tokio::runtime::Handle::current(),
        ));
        let responder = Arc::clone(&gateway);
        let completed = std::thread::spawn(move || {
            loop {
                if let Some(request) = responder.take_rejoin_request().unwrap() {
                    responder.complete_rejoin(request, true).unwrap();
                    break;
                }
                std::thread::yield_now();
            }
        });
        let epoch = CredentialServiceEpoch::from_bytes([9; 16]).unwrap();
        let mut attempts = 0_u8;

        let result = gateway.retry_metadata_after_rejoin(|| {
            attempts += 1;
            if attempts == 1 {
                (
                    Err(ProviderCredentialEnrollmentHostError::Unavailable),
                    Some(epoch),
                )
            } else {
                (Ok(true), None)
            }
        });

        completed.join().unwrap();
        assert_eq!(result, Ok(true));
        assert_eq!(attempts, 2);
    }
}
