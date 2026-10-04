use runne_application::provider::ProviderAdmissionError;

/// Store-issued, one-use permission to cross a provider effect boundary.
///
/// The value cannot be cloned or constructed outside this crate. Its check
/// runs synchronously at the final transport boundary, after asynchronous
/// request and credential preparation has completed.
pub struct ProviderFinalSendAuthority {
    consume: Option<Box<dyn FnOnce() -> Result<(), ProviderAdmissionError> + Send>>,
}

impl ProviderFinalSendAuthority {
    pub(crate) fn new(
        consume: impl FnOnce() -> Result<(), ProviderAdmissionError> + Send + 'static,
    ) -> Self {
        Self {
            consume: Some(Box::new(consume)),
        }
    }

    /// Revalidates and consumes this authority exactly once.
    pub fn consume(mut self) -> Result<(), ProviderAdmissionError> {
        self.consume
            .take()
            .ok_or(ProviderAdmissionError::AuthorityDenied)?()
    }
}

impl std::fmt::Debug for ProviderFinalSendAuthority {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("ProviderFinalSendAuthority(<opaque>)")
    }
}
