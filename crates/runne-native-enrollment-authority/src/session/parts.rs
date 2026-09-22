//! Authenticated writer session claim/effect context construction and the
//! macOS consumption splits.
//!
//! The types live in the parent `session` module; descendant modules may
//! construct their private fields, which keeps `from_split` inside the
//! session boundary without any public raw-parts constructor.

use runne_provider::CredentialWriterClaimIssuer;
use runne_provider::CredentialWriterEffectAuthority;

use super::{AuthenticatedWriterClaimContext, AuthenticatedWriterEffectAdmission};

#[cfg(target_os = "macos")]
type ClaimNativeParts = (
    std::os::unix::net::UnixStream,
    runne_provider::BrokerChannelBinding,
    runne_provider::PendingCredentialIssueTicketV1,
    runne_api::VerifiedSignedInstalledReleaseV2,
);
#[cfg(target_os = "linux")]
use super::LinuxClaimNative as ClaimNativeParts;

impl AuthenticatedWriterClaimContext {
    /// Sole constructor: pairs the fresh claim issuer with the native parts
    /// destructured from one authenticated session by `split()`.
    pub(super) const fn from_split(
        issuer: CredentialWriterClaimIssuer,
        #[cfg(any(target_os = "macos", target_os = "linux"))] native: Option<ClaimNativeParts>,
    ) -> Self {
        Self {
            issuer,
            #[cfg(any(target_os = "macos", target_os = "linux"))]
            native,
        }
    }
}

impl AuthenticatedWriterEffectAdmission {
    /// Sole constructor: pairs the fresh effect authority with the verified
    /// packaged executable paths destructured from the same session.
    pub(super) const fn from_split(
        effects: CredentialWriterEffectAuthority,
        #[cfg(any(target_os = "macos", target_os = "linux"))] native_paths: Option<(
            std::path::PathBuf,
            std::path::PathBuf,
        )>,
    ) -> Self {
        Self {
            effects,
            #[cfg(any(target_os = "macos", target_os = "linux"))]
            native_paths,
        }
    }
}

#[cfg(target_os = "macos")]
impl AuthenticatedWriterClaimContext {
    /// Consumes the claim side into the already-authenticated native channel.
    ///
    /// # Errors
    ///
    /// Rejects synthetic or incomplete contexts before any broker frame write.
    #[doc(hidden)]
    #[allow(
        clippy::type_complexity,
        reason = "the secure-store admission keeps the resources move-only"
    )]
    pub fn into_macos_claim_parts(
        self,
    ) -> Result<
        (
            CredentialWriterClaimIssuer,
            std::os::unix::net::UnixStream,
            runne_provider::BrokerChannelBinding,
            runne_provider::PendingCredentialIssueTicketV1,
            runne_api::VerifiedSignedInstalledReleaseV2,
        ),
        runne_macos_process_identity::MacOsPackagedWriterObservationError,
    > {
        let (control, channel, ticket, release) = self
            .native
            .ok_or(runne_macos_process_identity::MacOsPackagedWriterObservationError::Rejected)?;
        Ok((self.issuer, control, channel, ticket, release))
    }
}

#[cfg(target_os = "macos")]
impl AuthenticatedWriterEffectAdmission {
    /// Consumes the effect side with the two verified packaged executable paths.
    ///
    /// # Errors
    ///
    /// Rejects synthetic or incomplete contexts before native-store construction.
    #[doc(hidden)]
    pub fn into_macos_effect_parts(
        self,
    ) -> Result<
        (
            CredentialWriterEffectAuthority,
            std::path::PathBuf,
            std::path::PathBuf,
        ),
        runne_macos_process_identity::MacOsPackagedWriterObservationError,
    > {
        let (writer, reader) = self
            .native_paths
            .ok_or(runne_macos_process_identity::MacOsPackagedWriterObservationError::Rejected)?;
        Ok((self.effects, writer, reader))
    }
}
