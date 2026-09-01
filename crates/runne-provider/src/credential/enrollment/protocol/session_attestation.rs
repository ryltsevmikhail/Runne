use crate::credential::enrollment::CredentialBindingDigest;

mod claims;
mod codec;
#[cfg(any(test, feature = "test-support"))]
mod fixture;
mod issue_ticket;
mod matchers;
mod signer;

pub use claims::{
    CredentialWriterSessionAttestationClaimsV1, CredentialWriterSessionProcessClaimsV1,
    CredentialWriterSessionRuntimeClaimsV1, CredentialWriterSessionTicketClaimsV1,
};
pub use codec::CredentialWriterSessionAttestationCodec;
#[cfg(any(test, feature = "test-support"))]
pub(super) use fixture::attested_publication_signer_for_test;
pub use issue_ticket::{CredentialIssueTicketBindingV1, PendingCredentialIssueTicketV1};
pub use signer::CredentialWriterSessionAttestationSigner;

/// Inert signed session record; decoding it grants no writer authority.
///
/// ```compile_fail
/// fn raw_getters(value: &runne_provider::SignedCredentialWriterSessionAttestationV1) {
///     let _ = value.binding_digest();
///     let _ = value.ticket_claims();
///     let _ = value.runtime_claims();
///     let _ = value.process_claims();
///     let _ = value.channel_binding();
///     let _ = value.publication_public_key();
/// }
/// ```
/// ```compile_fail
/// fn no_current_time_predicate(value: &runne_provider::SignedCredentialWriterSessionAttestationV1) {
///     let _ = value.matches_current_time(0);
/// }
/// ```
pub struct SignedCredentialWriterSessionAttestationV1 {
    pub(super) claims: CredentialWriterSessionAttestationClaimsV1,
    pub(super) channel: CredentialBindingDigest,
    pub(super) publication_public_key: [u8; 32],
    pub(super) signature: [u8; 64],
}

impl core::fmt::Debug for SignedCredentialWriterSessionAttestationV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("SignedCredentialWriterSessionAttestationV1(<inert-signed>)")
    }
}
