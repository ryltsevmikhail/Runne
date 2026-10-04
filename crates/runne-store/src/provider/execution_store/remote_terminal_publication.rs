fn publication_code(disposition: runne_provider::ProviderRemotePublicationDisposition) -> i64 {
    match disposition {
        runne_provider::ProviderRemotePublicationDisposition::Allowed => 0,
        runne_provider::ProviderRemotePublicationDisposition::Rejected(
            runne_provider::ScannerTerminalDisposition::OutputLimitExceeded,
        ) => 1,
        runne_provider::ProviderRemotePublicationDisposition::Rejected(
            runne_provider::ScannerTerminalDisposition::Uncertain(
                runne_provider::ScannerUncertainReason::SecretDetected,
            ),
        ) => 2,
        runne_provider::ProviderRemotePublicationDisposition::Rejected(
            runne_provider::ScannerTerminalDisposition::Uncertain(
                runne_provider::ScannerUncertainReason::CredentialMatcherUnavailable,
            ),
        ) => 3,
        runne_provider::ProviderRemotePublicationDisposition::Rejected(
            runne_provider::ScannerTerminalDisposition::Uncertain(
                runne_provider::ScannerUncertainReason::RedactionScannerUnavailable,
            ),
        ) => 4,
        runne_provider::ProviderRemotePublicationDisposition::Rejected(
            runne_provider::ScannerTerminalDisposition::Uncertain(
                runne_provider::ScannerUncertainReason::CheckpointSecretStateUnavailable,
            ),
        ) => 5,
        runne_provider::ProviderRemotePublicationDisposition::Rejected(
            runne_provider::ScannerTerminalDisposition::Completed,
        ) => 0,
    }
}
