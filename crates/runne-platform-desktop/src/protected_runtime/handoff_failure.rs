use super::{CredentialWriterHandoff, ProtectedBundledRuntimeError};

/// Failed handoff, retaining wait ownership after signal authority was relinquished.
#[derive(Debug)]
#[must_use = "retained writer cleanup must be reaped or transferred to a cleanup registry"]
pub struct CredentialWriterHandoffError {
    error: ProtectedBundledRuntimeError,
    retained: Option<CredentialWriterHandoff>,
}

impl CredentialWriterHandoffError {
    pub(super) const fn retaining(
        error: ProtectedBundledRuntimeError,
        retained: CredentialWriterHandoff,
    ) -> Self {
        Self {
            error,
            retained: Some(retained),
        }
    }

    /// Closed error category, without releasing retained process ownership.
    #[must_use]
    pub const fn error(&self) -> &ProtectedBundledRuntimeError {
        &self.error
    }

    /// Transfers cleanup ownership to the caller even when handoff failed.
    #[must_use]
    pub fn into_parts(
        self,
    ) -> (
        ProtectedBundledRuntimeError,
        Option<CredentialWriterHandoff>,
    ) {
        (self.error, self.retained)
    }
}

impl From<ProtectedBundledRuntimeError> for CredentialWriterHandoffError {
    fn from(error: ProtectedBundledRuntimeError) -> Self {
        Self {
            error,
            retained: None,
        }
    }
}

pub(super) const fn finish(
    handoff: CredentialWriterHandoff,
    result: Result<(), ProtectedBundledRuntimeError>,
) -> Result<CredentialWriterHandoff, CredentialWriterHandoffError> {
    match result {
        Ok(()) => Ok(handoff),
        Err(error) => Err(CredentialWriterHandoffError::retaining(error, handoff)),
    }
}

/// Real wait owner in a synthetic failed handoff; no native authority or secret effect.
///
/// # Panics
/// Panics if the disposable child cannot be spawned.
#[cfg(feature = "test-support")]
pub fn test_only_failed_writer_handoff() -> (std::process::Child, CredentialWriterHandoffError) {
    let child = std::process::Command::new("/bin/sleep")
        .arg("30")
        .spawn()
        .expect("disposable writer child");
    let owner = crate::provider_credential_broker::MacOsWriterReapOnlyOwner::test_child(child.id());
    let error = finish(
        CredentialWriterHandoff {
            owner: Some(owner),
            pair_relay: None,
        },
        Err(ProtectedBundledRuntimeError::OwnershipMismatch),
    )
    .unwrap_err();
    (child, error)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn failed_final_ack_keeps_exact_reap_owner() {
        let mut child = std::process::Command::new("/bin/sleep")
            .arg("30")
            .spawn()
            .unwrap();
        let owner =
            crate::provider_credential_broker::MacOsWriterReapOnlyOwner::test_child(child.id());
        let handoff = CredentialWriterHandoff {
            owner: Some(owner),
            pair_relay: None,
        };
        let result = finish(
            handoff,
            Err(ProtectedBundledRuntimeError::OwnershipMismatch),
        );
        let (_, retained) = result.unwrap_err().into_parts();
        if retained.is_none() {
            child.kill().unwrap();
            child.wait().unwrap();
        }
        let mut retained = retained.expect("post-relinquishment failure retains exact wait owner");
        let pending = retained.reap_exact_writer_bounded(std::time::Duration::ZERO);
        child.kill().unwrap();
        retained.reap_exact_writer().unwrap();
        assert!(
            pending.is_err(),
            "live child must remain addressable after a bounded timeout"
        );
        assert!(retained.owner.is_none());
        retained.reap_exact_writer().unwrap();
        assert_eq!(child.wait().unwrap_err().raw_os_error(), Some(libc::ECHILD));
    }
}
