use super::*;

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum InitialCredentialExchange {
    Intent,
    Recovery,
}

impl DaemonProtectedCredentialEnrollmentSession {
    pub(crate) fn accept_initial_request(
        &mut self,
        frame: &[u8],
        now_millis: u64,
    ) -> Result<(InitialCredentialExchange, Vec<u8>), ProviderCredentialEnrollmentHostError> {
        if runne_api::ProtectedCredentialRecoveryCodec::recognizes_frame(frame) {
            return self
                .offer_cleanup_recovery(frame, now_millis / 1000)
                .map(|frame| (InitialCredentialExchange::Recovery, frame));
        }
        self.accept_request(frame, now_millis)
            .map(|frame| (InitialCredentialExchange::Intent, frame))
    }
}
