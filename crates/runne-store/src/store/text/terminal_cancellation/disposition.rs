pub(super) fn terminal_disposition_code(
    disposition: runne_provider::ProviderTerminalDisposition,
) -> i64 {
    match disposition {
        runne_provider::ProviderTerminalDisposition::Completed => 1,
        runne_provider::ProviderTerminalDisposition::RemoteFailed => 2,
        runne_provider::ProviderTerminalDisposition::RemoteIncomplete => 3,
        runne_provider::ProviderTerminalDisposition::CancelledUncertain => 4,
    }
}
