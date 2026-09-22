//! Linux writer session claim/effect splits.
//!
//! Mirrors the macOS `into_macos_*_parts` surface with the accepted Linux
//! fact sources: the daemon-attested local content pin (release tuple digest
//! = build-time canonical digest set; candidate = writer image digest) and
//! the pidfd-owned writer process. The release pin is NEVER a signer
//! identity.

use runne_provider::CredentialWriterClaimIssuer;
use runne_provider::CredentialWriterEffectAuthority;

use super::{AuthenticatedWriterClaimContext, AuthenticatedWriterEffectAdmission};

#[cfg(target_os = "linux")]
impl AuthenticatedWriterClaimContext {
    /// Consumes the claim side into the already-authenticated Linux channel
    /// parts; the ticket arrives ALREADY BOUND by the self-contained
    /// authenticated receiver — no raw record or arrays ever cross this
    /// boundary.
    ///
    /// # Errors
    ///
    /// Rejects synthetic or incomplete contexts before any broker frame write.
    #[doc(hidden)]
    pub fn into_linux_claim_parts(
        self,
    ) -> Result<
        (
            CredentialWriterClaimIssuer,
            std::os::unix::net::UnixStream,
            runne_provider::BrokerChannelBinding,
            runne_provider::PendingCredentialIssueTicketV1,
        ),
        &'static str,
    > {
        let (control, channel, ticket) =
            self.native.ok_or("linux session verified parts absent")?;
        Ok((self.issuer, control, channel, ticket))
    }
}

#[cfg(target_os = "linux")]
impl AuthenticatedWriterEffectAdmission {
    /// Consumes the effect side with the two verified executable paths.
    ///
    /// # Errors
    ///
    /// Rejects synthetic or incomplete contexts before native-store construction.
    #[doc(hidden)]
    pub fn into_linux_effect_parts(
        self,
    ) -> Result<
        (
            CredentialWriterEffectAuthority,
            std::path::PathBuf,
            std::path::PathBuf,
        ),
        &'static str,
    > {
        let (writer, reader) = self
            .native_paths
            .ok_or("linux session verified parts absent")?;
        Ok((self.effects, writer, reader))
    }
}
