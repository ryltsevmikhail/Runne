use runne_provider::{
    CredentialMatcher, DispatchAttemptId, ScannerTerminalDisposition, TailBinding,
    scan_provider_chunk,
};
use zeroize::Zeroizing;

/// Scans one complete remote snapshot independently of the foreground stream cursor.
pub fn scan_complete_provider_snapshot<M: CredentialMatcher + ?Sized>(
    matcher: &M,
    text: &str,
) -> Result<String, ScannerTerminalDisposition> {
    let epoch = matcher.epoch().map_err(|_| {
        ScannerTerminalDisposition::Uncertain(
            runne_provider::ScannerUncertainReason::CredentialMatcherUnavailable,
        )
    })?;
    let binding = TailBinding::new(
        DispatchAttemptId::from_bytes([0; 16]),
        1,
        epoch,
        epoch,
        1,
        0,
    )
    .map_err(|_| {
        ScannerTerminalDisposition::Uncertain(
            runne_provider::ScannerUncertainReason::RedactionScannerUnavailable,
        )
    })?;
    let step = scan_provider_chunk(
        matcher,
        binding,
        Zeroizing::new(Vec::new()),
        text.as_bytes(),
        0,
    )
    .map_err(|_| {
        ScannerTerminalDisposition::Uncertain(
            runne_provider::ScannerUncertainReason::RedactionScannerUnavailable,
        )
    })?;
    if let Some(disposition) = step.disposition() {
        return Err(disposition);
    }
    let mut safe = Zeroizing::new(step.safe_prefix().to_vec());
    safe.extend_from_slice(&step.into_withheld_tail());
    String::from_utf8(safe.to_vec()).map_err(|_| {
        ScannerTerminalDisposition::Uncertain(
            runne_provider::ScannerUncertainReason::RedactionScannerUnavailable,
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use runne_provider::{ScannerError, ScannerUncertainReason};

    struct NeedleMatcher(&'static [u8]);

    impl CredentialMatcher for NeedleMatcher {
        fn epoch(&self) -> Result<u64, ScannerError> {
            Ok(1)
        }

        fn maximum_match_len(&self) -> Result<usize, ScannerError> {
            Ok(self.0.len())
        }

        fn contains_match(&self, bytes: &[u8]) -> Result<bool, ScannerError> {
            Ok(bytes.windows(self.0.len()).any(|window| window == self.0))
        }
    }

    #[test]
    fn scans_the_complete_snapshot_without_mutating_a_foreground_cursor() {
        let text = format!("{}{}", "safe-prefix/".repeat(40), "exact-complete-output");
        assert_eq!(
            scan_complete_provider_snapshot(&NeedleMatcher(b"secret"), &text).unwrap(),
            text,
        );
        assert_eq!(
            scan_complete_provider_snapshot(&NeedleMatcher(b"secret"), "safe-secret-tail"),
            Err(ScannerTerminalDisposition::Uncertain(
                ScannerUncertainReason::SecretDetected
            )),
        );
    }
}
