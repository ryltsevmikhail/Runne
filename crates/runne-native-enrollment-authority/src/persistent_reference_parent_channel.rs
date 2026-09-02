use std::num::NonZeroU32;

/// Validates the feasibility probe's inherited channel without granting authority.
///
/// # Errors
///
/// Fails closed unless stdin's kernel-audited peer is the exact fixture-validated
/// package parent in the same session.
pub fn validate_persistent_reference_parent_channel(
    expected_parent: NonZeroU32,
) -> Result<(), runne_macos_process_identity::MacOsLocalPeerProcessIdentityError> {
    let stdin = std::io::stdin();
    runne_macos_process_identity::validate_current_parent_channel(&stdin, expected_parent)
}
