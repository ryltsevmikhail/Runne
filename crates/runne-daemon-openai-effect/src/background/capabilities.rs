use runne_provider::ProviderRecoveryCapabilities;

/// Static controls supported by the compiled OpenAI background adapter.
#[doc(hidden)]
pub fn background_recovery_capabilities() -> ProviderRecoveryCapabilities {
    ProviderRecoveryCapabilities {
        status_check: true,
        stream_resume: false,
        remote_cancel: true,
    }
}
