//! One-shot claimed writer execution.

use std::io::Read;

use super::{
    CliError,
    claim::ClaimedWriterControl,
    effect::{execute_non_pair_effect, execute_pair_effect},
};

#[cfg(target_os = "macos")]
use runne_provider::CredentialSecretInputPresence;
#[cfg(target_os = "macos")]
use runne_secure_store::NativeProviderCredentialWriters;

#[cfg(target_os = "macos")]
use super::{channel::InheritedSecretInputSlot, claim::claim_writer_authorization};

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

/// Reauthenticates one pinned macOS writer, claims its retained ticket, and
/// only then adopts Pair fd 3 or executes a control-only non-Pair effect.
#[cfg(target_os = "macos")]
pub fn run_authenticated_writer(
    pinned: runne_native_enrollment_authority::PendingPinnedProviderCredentialWriterSessionV1,
    secret: InheritedSecretInputSlot,
) -> Result<(), CliError> {
    let presence = secret.presence();
    let session = pinned
        .authenticate_current_writer()
        .map_err(|_| CliError::CredentialOperation)?;
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
