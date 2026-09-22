//! One-shot claimed writer execution.

use std::io::Read;

use super::{
    CliError,
    claim::ClaimedWriterControl,
    effect::{execute_non_pair_effect, execute_pair_effect},
};

#[cfg(any(target_os = "macos", target_os = "linux"))]
use runne_provider::CredentialSecretInputPresence;
#[cfg(any(target_os = "macos", target_os = "linux"))]
use runne_secure_store::NativeProviderCredentialWriters;

#[cfg(any(target_os = "macos", target_os = "linux"))]
use super::channel::InheritedSecretInputSlot;
#[cfg(any(target_os = "macos", target_os = "linux"))]
use super::claim::claim_writer_authorization;

/// Dispatches one already-claimed writer by the presence policy that the
/// retained ticket accepted before claim.
pub fn execute_claimed_writer<R: Read>(
    claimed: ClaimedWriterControl,
    mut secret: Option<R>,
) -> Result<(), CliError> {
    match secret.as_mut() {
        Some(reader) => execute_pair_effect(claimed.read_pair_secret(reader)?),
        None => execute_non_pair_effect(claimed.authorize_without_secret()?),
    }
}

/// Runs one Linux authenticated session through the shared claim/effect path.
#[cfg(target_os = "linux")]
pub fn run_linux_authenticated_writer(
    session: runne_native_enrollment_authority::AuthenticatedProviderCredentialWriterSession,
    secret: InheritedSecretInputSlot,
) -> Result<(), CliError> {
    run_session(session, secret)
}

#[cfg(target_os = "macos")]
pub fn run_authenticated_writer(
    pinned: runne_native_enrollment_authority::PendingPinnedProviderCredentialWriterSessionV1,
    secret: InheritedSecretInputSlot,
) -> Result<(), CliError> {
    let session = pinned
        .authenticate_current_writer()
        .map_err(|_| CliError::CredentialOperation)?;
    run_session(session, secret)
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
fn run_session(
    session: runne_native_enrollment_authority::AuthenticatedProviderCredentialWriterSession,
    secret: InheritedSecretInputSlot,
) -> Result<(), CliError> {
    let presence = secret.presence();
    let writers = NativeProviderCredentialWriters::from_authenticated_session(session)
        .map_err(|_| CliError::CredentialOperation)?;
    let claimed = claim_writer_authorization(writers, presence)?;
    match presence {
        CredentialSecretInputPresence::Present => {
            execute_claimed_writer(claimed, Some(secret.adopt()?))
        }
        CredentialSecretInputPresence::Absent => {
            execute_claimed_writer::<std::io::Empty>(claimed, None)
        }
    }
}
