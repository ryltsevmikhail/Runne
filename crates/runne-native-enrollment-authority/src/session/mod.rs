#[cfg(any(test, any(target_os = "macos", target_os = "linux")))]
use runne_provider::CredentialWriterAuthorityPair;
use runne_provider::{
    CredentialBindingDigest, CredentialWriterClaimIssuer, CredentialWriterEffectAuthority,
};

#[cfg(target_os = "linux")]
type LinuxSessionParts = Box<(
    std::os::unix::net::UnixStream,
    runne_provider::BrokerChannelBinding,
    runne_provider::PendingCredentialIssueTicketV1,
    std::path::PathBuf,
    std::path::PathBuf,
)>;
#[cfg(target_os = "linux")]
type LinuxClaimNative = (
    std::os::unix::net::UnixStream,
    runne_provider::BrokerChannelBinding,
    runne_provider::PendingCredentialIssueTicketV1,
);

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
    #[cfg(target_os = "linux")]
    Linux(LinuxSessionParts),
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
        not(any(test, target_os = "macos", target_os = "linux")),
        expect(
            dead_code,
            reason = "opaque claim surface is retained until a platform verifier is wired"
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
    #[cfg(target_os = "linux")]
    native: Option<LinuxClaimNative>,
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
        not(any(test, target_os = "macos", target_os = "linux")),
        expect(
            dead_code,
            reason = "opaque effect surface is retained until a platform verifier is wired"
        )
    )]
    effects: CredentialWriterEffectAuthority,
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    native_paths: Option<(std::path::PathBuf, std::path::PathBuf)>,
}

impl AuthenticatedProviderCredentialWriterSession {
    #[cfg(any(test, any(target_os = "macos", target_os = "linux")))]
    #[allow(
        clippy::redundant_pub_crate,
        reason = "the sibling verifiers are the sole production callers"
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
    #[cfg_attr(
        not(any(test, target_os = "macos", target_os = "linux")),
        expect(
            clippy::missing_const_for_fn,
            reason = "the shared opaque API performs non-const authority creation on native platforms"
        )
    )]
    pub fn split(
        self,
    ) -> (
        AuthenticatedWriterClaimContext,
        AuthenticatedWriterEffectAdmission,
    ) {
        #[cfg(not(any(test, target_os = "macos", target_os = "linux")))]
        {
            match self.verified {}
        }
        #[cfg(any(test, target_os = "macos", target_os = "linux"))]
        {
            #[cfg(any(target_os = "macos", target_os = "linux"))]
            let (native, native_paths) = match self.verified {
                #[cfg(target_os = "macos")]
                VerifiedEnrollmentSession::MacOs(parts) => {
                    let (control, channel, ticket, writer, reader, release) = *parts;
                    (
                        Some((control, channel, ticket, release)),
                        Some((writer, reader)),
                    )
                }
                #[cfg(target_os = "linux")]
                VerifiedEnrollmentSession::Linux(parts) => {
                    let (control, channel, ticket, writer, reader) = *parts;
                    (Some((control, channel, ticket)), Some((writer, reader)))
                }
                #[cfg(test)]
                VerifiedEnrollmentSession::Verified => (None, None),
            };
            let pair = CredentialWriterAuthorityPair::new();
            let (issuer, effects) = pair.split();
            (
                AuthenticatedWriterClaimContext::from_split(
                    issuer,
                    #[cfg(any(target_os = "macos", target_os = "linux"))]
                    native,
                ),
                AuthenticatedWriterEffectAdmission::from_split(
                    effects,
                    #[cfg(any(target_os = "macos", target_os = "linux"))]
                    native_paths,
                ),
            )
        }
    }
}

#[cfg(target_os = "linux")]
mod linux_parts;

#[cfg(target_os = "linux")]
mod linux_entry;

#[cfg(target_os = "linux")]
mod linux_verifier;

#[cfg(all(test, target_os = "linux"))]
mod linux_verifier_tests;
#[cfg(any(test, target_os = "macos", target_os = "linux"))]
mod parts;
#[cfg(test)]
mod tests;
