use runne_provider::{
    CredentialWriterAuthorityPair, CredentialWriterClaimIssuer, CredentialWriterEffectAuthority,
};

#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "B2b will construct this only after live process and release verification"
    )
)]
enum VerifiedEnrollmentSession {
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
#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "B2b will add the authenticated CLI claim consumer"
    )
)]
pub struct AuthenticatedWriterClaimContext {
    issuer: CredentialWriterClaimIssuer,
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
#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "B2b will add the authenticated secure-store effect consumer"
    )
)]
pub struct AuthenticatedWriterEffectAdmission {
    effects: CredentialWriterEffectAuthority,
}

impl AuthenticatedProviderCredentialWriterSession {
    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "B2b verifier will be the sole production caller of this private mint"
        )
    )]
    const fn mint(verified: VerifiedEnrollmentSession) -> Self {
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
        let pair = match self.verified {
            VerifiedEnrollmentSession::Verified => CredentialWriterAuthorityPair::new(),
        };
        let (issuer, effects) = pair.split();
        (
            AuthenticatedWriterClaimContext { issuer },
            AuthenticatedWriterEffectAdmission { effects },
        )
    }
}

#[cfg(test)]
#[path = "session_tests.rs"]
mod tests;
