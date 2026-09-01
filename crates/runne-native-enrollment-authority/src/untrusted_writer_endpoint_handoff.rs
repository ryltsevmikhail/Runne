//! Neutral authority staging for an untrusted native writer handoff.

/// An opaque, unauthenticated writer endpoint received from native ingress.
///
/// This value grants no provider credential authority. It is retained only so
/// a later verifier can consume it without exposing descriptor or frame data.
///
/// ```compile_fail
/// fn require_clone<T: Clone>() {}
/// require_clone::<runne_native_enrollment_authority::UntrustedProviderCredentialWriterEndpointHandoffV1>();
/// ```
///
/// ```compile_fail
/// fn require_copy<T: Copy>() {}
/// require_copy::<runne_native_enrollment_authority::UntrustedProviderCredentialWriterEndpointHandoffV1>();
/// ```
///
/// ```compile_fail
/// fn require_debug<T: std::fmt::Debug>() {}
/// require_debug::<runne_native_enrollment_authority::UntrustedProviderCredentialWriterEndpointHandoffV1>();
/// ```
///
/// ```compile_fail
/// fn require_default<T: Default>() {}
/// require_default::<runne_native_enrollment_authority::UntrustedProviderCredentialWriterEndpointHandoffV1>();
/// ```
///
/// ```compile_fail
/// fn require_serialize<T: serde::Serialize>() {}
/// require_serialize::<runne_native_enrollment_authority::UntrustedProviderCredentialWriterEndpointHandoffV1>();
/// ```
///
/// ```compile_fail
/// fn require_deserialize<T: serde::de::DeserializeOwned>() {}
/// require_deserialize::<runne_native_enrollment_authority::UntrustedProviderCredentialWriterEndpointHandoffV1>();
/// ```
///
/// ```compile_fail
/// fn require_as_fd<T: std::os::fd::AsFd>() {}
/// require_as_fd::<runne_native_enrollment_authority::UntrustedProviderCredentialWriterEndpointHandoffV1>();
/// ```
///
/// ```compile_fail
/// fn require_as_raw_fd<T: std::os::fd::AsRawFd>() {}
/// require_as_raw_fd::<runne_native_enrollment_authority::UntrustedProviderCredentialWriterEndpointHandoffV1>();
/// ```
///
/// ```compile_fail
/// fn require_into_raw_fd<T: std::os::fd::IntoRawFd>() {}
/// require_into_raw_fd::<runne_native_enrollment_authority::UntrustedProviderCredentialWriterEndpointHandoffV1>();
/// ```
///
/// ```compile_fail
/// use runne_native_enrollment_authority::UntrustedProviderCredentialWriterEndpointHandoffV1;
/// let _ = UntrustedProviderCredentialWriterEndpointHandoffV1 { inner: panic!() };
/// ```
///
/// ```compile_fail
/// use runne_native_enrollment_authority::UntrustedProviderCredentialWriterEndpointHandoffV1;
/// let _ = UntrustedProviderCredentialWriterEndpointHandoffV1::from_parts();
/// ```
///
/// ```compile_fail
/// fn raw_getters(value: &runne_native_enrollment_authority::UntrustedProviderCredentialWriterEndpointHandoffV1) {
///     let _ = value.as_fd();
///     let _ = value.as_raw_fd();
///     let _ = value.frame();
///     let _ = value.control();
///     let _ = value.handoff_digest();
/// }
/// ```
///
/// ```compile_fail
/// use runne_native_enrollment_authority::{AuthenticatedProviderCredentialWriterSession, UntrustedProviderCredentialWriterEndpointHandoffV1};
/// fn authenticate(value: UntrustedProviderCredentialWriterEndpointHandoffV1) {
///     let _: AuthenticatedProviderCredentialWriterSession = value.into();
/// }
/// ```
///
/// ```compile_fail
/// use runne_native_enrollment_authority::{AuthenticatedWriterClaimContext, UntrustedProviderCredentialWriterEndpointHandoffV1};
/// fn authenticate(value: UntrustedProviderCredentialWriterEndpointHandoffV1) {
///     let _: AuthenticatedWriterClaimContext = value.into();
/// }
/// ```
///
/// ```compile_fail
/// use runne_native_enrollment_authority::{AuthenticatedWriterEffectAdmission, UntrustedProviderCredentialWriterEndpointHandoffV1};
/// fn authenticate(value: UntrustedProviderCredentialWriterEndpointHandoffV1) {
///     let _: AuthenticatedWriterEffectAdmission = value.into();
/// }
/// ```
#[doc(hidden)]
pub struct UntrustedProviderCredentialWriterEndpointHandoffV1 {
    #[allow(dead_code)]
    inner: runne_macos_process_identity::MacOsUntrustedWriterEndpointHandoffV1,
}

/// Opaque pinned native session that still grants no credential authority.
///
/// ```compile_fail
/// fn require_clone<T: Clone>() {}
/// require_clone::<runne_native_enrollment_authority::PendingPinnedProviderCredentialWriterSessionV1>();
/// ```
///
/// ```compile_fail
/// fn require_default<T: Default>() {}
/// require_default::<runne_native_enrollment_authority::PendingPinnedProviderCredentialWriterSessionV1>();
/// ```
///
/// ```compile_fail
/// use runne_native_enrollment_authority::PendingPinnedProviderCredentialWriterSessionV1;
/// let _ = PendingPinnedProviderCredentialWriterSessionV1 { inner: panic!() };
/// ```
///
/// ```compile_fail
/// fn no_mint(value: runne_native_enrollment_authority::PendingPinnedProviderCredentialWriterSessionV1) {
///     let _ = value.mint();
///     let _ = value.into_authority();
/// }
/// ```
#[doc(hidden)]
pub struct PendingPinnedProviderCredentialWriterSessionV1 {
    #[allow(dead_code)]
    inner: runne_macos_process_identity::MacOsPendingProvisionalWriterSessionV1,
}

impl UntrustedProviderCredentialWriterEndpointHandoffV1 {
    /// Receives one fixed, unauthenticated handoff from this process's stdin.
    ///
    /// # Errors
    ///
    /// Fails closed unless native ingress yields its exact bounded record.
    #[doc(hidden)]
    pub fn receive_from_stdin() -> std::io::Result<Self> {
        runne_macos_process_identity::MacOsUntrustedWriterEndpointHandoffV1::receive_from_stdin()
            .map(|inner| Self { inner })
    }

    /// Consumes the handoff through pinned release and live native verification.
    ///
    /// # Errors
    ///
    /// Fails closed for malformed bootstrap evidence, unavailable compiled trust,
    /// stale metadata or attestation, release mismatch, or native identity drift.
    #[doc(hidden)]
    pub fn observe_current_pinned_writer_session(
        self,
    ) -> Result<
        PendingPinnedProviderCredentialWriterSessionV1,
        runne_macos_process_identity::MacOsPackagedWriterObservationError,
    > {
        let transcript = self.inner.observe_pending_writer_bootstrap()?;
        let (pending_match, metadata) = transcript.into_release_verification();
        pending_match
            .match_current_pinned_release(metadata)
            .map(|inner| PendingPinnedProviderCredentialWriterSessionV1 { inner })
    }
}
