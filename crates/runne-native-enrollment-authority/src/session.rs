#[cfg(any(test, target_os = "macos"))]
use runne_provider::CredentialWriterAuthorityPair;
use runne_provider::{CredentialWriterClaimIssuer, CredentialWriterEffectAuthority};

#[allow(
    clippy::redundant_pub_crate,
    reason = "the sibling verifier is the sole constructor boundary"
)]
pub(crate) enum VerifiedEnrollmentSession {
    #[cfg(target_os = "macos")]
    MacOs(
        Box<(
            std::os::unix::net::UnixStream,
            runne_provider::BrokerChannelBinding,
            runne_provider::PendingCredentialIssueTicketV1,
            std::path::PathBuf,
            std::path::PathBuf,
            runne_api::VerifiedSignedInstalledReleaseV2,
        )>,
    ),
    #[cfg(test)]
    Verified,
}

/// One authenticated packaged-writer session that can be split exactly once.
///
/// The value has no raw public constructor and cannot be cloned or serialized.
///
/// ```compile_fail
/// fn require_clone<T: Clone>() {}
/// require_clone::<runne_native_enrollment_authority::AuthenticatedProviderCredentialWriterSession>();
/// ```
/// ```compile_fail
/// fn require_serialize<T: serde::Serialize>() {}
/// require_serialize::<runne_native_enrollment_authority::AuthenticatedProviderCredentialWriterSession>();
/// ```
/// ```compile_fail
/// fn require_deserialize<T: serde::de::DeserializeOwned>() {}
/// require_deserialize::<runne_native_enrollment_authority::AuthenticatedProviderCredentialWriterSession>();
/// ```
/// ```compile_fail
/// fn require_default<T: Default>() {}
/// require_default::<runne_native_enrollment_authority::AuthenticatedProviderCredentialWriterSession>();
/// ```
/// ```compile_fail
/// use runne_native_enrollment_authority::AuthenticatedProviderCredentialWriterSession;
/// let _ = AuthenticatedProviderCredentialWriterSession::new();
/// ```
/// ```compile_fail
/// use runne_native_enrollment_authority::AuthenticatedProviderCredentialWriterSession;
/// let _ = AuthenticatedProviderCredentialWriterSession { verified: panic!("private") };
/// ```
/// ```compile_fail
/// use runne_native_enrollment_authority::AuthenticatedProviderCredentialWriterSession;
/// fn split_twice(session: AuthenticatedProviderCredentialWriterSession) {
///     let _ = session.split();
///     let _ = session.split();
/// }
/// ```
pub struct AuthenticatedProviderCredentialWriterSession {
    verified: VerifiedEnrollmentSession,
}

/// Claim-side context created from one authenticated writer session.
///
/// ```compile_fail
/// fn require_clone<T: Clone>() {}
/// require_clone::<runne_native_enrollment_authority::AuthenticatedWriterClaimContext>();
/// ```
/// ```compile_fail
/// fn require_serialize<T: serde::Serialize>() {}
/// require_serialize::<runne_native_enrollment_authority::AuthenticatedWriterClaimContext>();
/// ```
/// ```compile_fail
/// fn require_deserialize<T: serde::de::DeserializeOwned>() {}
/// require_deserialize::<runne_native_enrollment_authority::AuthenticatedWriterClaimContext>();
/// ```
/// ```compile_fail
/// fn require_default<T: Default>() {}
/// require_default::<runne_native_enrollment_authority::AuthenticatedWriterClaimContext>();
/// ```
/// ```compile_fail
/// use runne_native_enrollment_authority::AuthenticatedWriterClaimContext;
/// let (issuer, _) = runne_provider::CredentialWriterAuthorityPair::new().split();
/// let _ = AuthenticatedWriterClaimContext::from_issuer(issuer);
/// ```
/// ```compile_fail
/// use runne_native_enrollment_authority::AuthenticatedWriterClaimContext;
/// let (issuer, _) = runne_provider::CredentialWriterAuthorityPair::new().split();
/// let _ = AuthenticatedWriterClaimContext { issuer };
/// ```
pub struct AuthenticatedWriterClaimContext {
    #[cfg_attr(
        not(any(test, target_os = "macos")),
        expect(
            dead_code,
            reason = "opaque claim surface is retained; only macOS can admit a native session"
        )
    )]
    issuer: CredentialWriterClaimIssuer,
    #[cfg(target_os = "macos")]
    native: Option<(
        std::os::unix::net::UnixStream,
        runne_provider::BrokerChannelBinding,
        runne_provider::PendingCredentialIssueTicketV1,
        runne_api::VerifiedSignedInstalledReleaseV2,
    )>,
}

/// Effect-side admission created from the same authenticated writer session.
///
/// ```compile_fail
/// fn require_clone<T: Clone>() {}
/// require_clone::<runne_native_enrollment_authority::AuthenticatedWriterEffectAdmission>();
/// ```
/// ```compile_fail
/// fn require_serialize<T: serde::Serialize>() {}
/// require_serialize::<runne_native_enrollment_authority::AuthenticatedWriterEffectAdmission>();
/// ```
/// ```compile_fail
/// fn require_deserialize<T: serde::de::DeserializeOwned>() {}
/// require_deserialize::<runne_native_enrollment_authority::AuthenticatedWriterEffectAdmission>();
/// ```
/// ```compile_fail
/// fn require_default<T: Default>() {}
/// require_default::<runne_native_enrollment_authority::AuthenticatedWriterEffectAdmission>();
/// ```
/// ```compile_fail
/// use runne_native_enrollment_authority::AuthenticatedWriterEffectAdmission;
/// let (_, effects) = runne_provider::CredentialWriterAuthorityPair::new().split();
/// let _ = AuthenticatedWriterEffectAdmission::from_effects(effects);
/// ```
/// ```compile_fail
/// use runne_native_enrollment_authority::AuthenticatedWriterEffectAdmission;
/// let (_, effects) = runne_provider::CredentialWriterAuthorityPair::new().split();
/// let _ = AuthenticatedWriterEffectAdmission { effects };
/// ```
pub struct AuthenticatedWriterEffectAdmission {
    #[cfg_attr(
        not(any(test, target_os = "macos")),
        expect(
            dead_code,
            reason = "opaque effect surface is retained; only macOS can admit a native session"
        )
    )]
    effects: CredentialWriterEffectAuthority,
    #[cfg(target_os = "macos")]
    native_paths: Option<(std::path::PathBuf, std::path::PathBuf)>,
}

impl AuthenticatedProviderCredentialWriterSession {
    #[cfg(any(test, target_os = "macos"))]
    #[allow(
        clippy::redundant_pub_crate,
        reason = "the sibling verifier is the sole production caller"
    )]
    pub(crate) const fn mint(verified: VerifiedEnrollmentSession) -> Self {
        Self { verified }
    }

    #[cfg(test)]
    const fn mint_for_test() -> Self {
        Self::mint(VerifiedEnrollmentSession::Verified)
    }

    /// Consumes the admitted session and creates one matched claim/effect pair.
    #[must_use]
    pub fn split(
        self,
    ) -> (
        AuthenticatedWriterClaimContext,
        AuthenticatedWriterEffectAdmission,
    ) {
        #[cfg(not(any(test, target_os = "macos")))]
        {
            match self.verified {}
        }
        #[cfg(any(test, target_os = "macos"))]
        {
            #[cfg(target_os = "macos")]
            let (native, native_paths) = match self.verified {
                #[cfg(target_os = "macos")]
                VerifiedEnrollmentSession::MacOs(parts) => {
                    let (control, channel, ticket, writer, reader, release) = *parts;
                    (
                        Some((control, channel, ticket, release)),
                        Some((writer, reader)),
                    )
                }
                #[cfg(test)]
                VerifiedEnrollmentSession::Verified => (None, None),
            };
            #[cfg(not(target_os = "macos"))]
            match self.verified {
                #[cfg(test)]
                VerifiedEnrollmentSession::Verified => {}
            }
            let pair = CredentialWriterAuthorityPair::new();
            let (issuer, effects) = pair.split();
            (
                AuthenticatedWriterClaimContext {
                    issuer,
                    #[cfg(target_os = "macos")]
                    native,
                },
                AuthenticatedWriterEffectAdmission {
                    effects,
                    #[cfg(target_os = "macos")]
                    native_paths,
                },
            )
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

#[cfg(test)]
#[path = "session_tests.rs"]
mod tests;
