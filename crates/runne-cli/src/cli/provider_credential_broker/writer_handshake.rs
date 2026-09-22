//! Linux writer startup + CONTROL receive: the ENTIRE trust path lives in
//! the authority crate's self-contained entry — the CLI only invokes it and
//! keeps the closed session alive for the process lifetime. No expected
//! keys, digests, sockets, or paths are controlled by this crate.

use runne_native_enrollment_authority::AuthenticatedProviderCredentialWriterSession;

use super::CliError;

/// Authenticates the inherited endpoints, then runs one claimed effect.
/// The secret pipe remains unread until the exact qualified claim succeeds.
pub(super) fn respond_startup_from_stdout(
    secret: super::channel::InheritedSecretInputSlot,
) -> Result<(), CliError> {
    let session =
        AuthenticatedProviderCredentialWriterSession::receive_linux_authenticated_writer()
            .map_err(|_| CliError::CredentialOperation)?;
    super::run::run_linux_authenticated_writer(session, secret)
}
