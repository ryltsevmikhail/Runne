use runne_api::ProviderCredentialProviderV2;

use super::profiles::{RemoteVerificationProfile, remote_profile};

#[test]
fn remote_profiles_are_explicitly_unsupported_without_a_qualified_authentication_probe() {
    for provider in [
        ProviderCredentialProviderV2::OpenAi,
        ProviderCredentialProviderV2::DeepSeek,
    ] {
        assert_eq!(
            remote_profile(provider),
            RemoteVerificationProfile::NoQualifiedAuthenticationProbe
        );
    }
}
