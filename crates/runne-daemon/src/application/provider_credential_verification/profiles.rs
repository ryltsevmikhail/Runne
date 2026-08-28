use runne_api::ProviderCredentialProviderV2;

/// Closed remote-verification profile state without transport details.
///
/// A provider receives no network request until this state is replaced by a
/// pinned, reviewed authentication probe profile.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RemoteVerificationProfile {
    /// No pinned primary contract defines a safe authentication probe.
    NoQualifiedAuthenticationProbe,
}

/// Returns the only reviewed remote profile for a supported provider.
#[must_use]
pub(crate) const fn remote_profile(
    _provider: ProviderCredentialProviderV2,
) -> RemoteVerificationProfile {
    RemoteVerificationProfile::NoQualifiedAuthenticationProbe
}
