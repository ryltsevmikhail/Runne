// Protected bundled-runtime activation wire and binding contracts.

use std::fmt;
use std::path::PathBuf;

use hmac::{Hmac, Mac};
use runne_domain::id::validate_uuid_v7_bytes;
use runne_plugin_protocol::cbor::{
    CborDecoder, CborEncoder, DecodeError, DeterministicCodec, EncodeError,
};
use runne_plugin_protocol::frame::{FrameLimits, decode_codec_frame, encode_codec_frame};
use runne_plugin_protocol::profile::DecodeLimits;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, Zeroizing};

const PROTOCOL_SCHEMA_VERSION: u32 = 1;
const PROTOCOL_SCHEMA_VERSION_V2: u32 = 2;
const MAX_FRAME_BYTES: usize = 65_540;
const MAX_PAYLOAD_BYTES: usize = 65_536;
const MAX_TEXT_BYTES: usize = 4_096;
const MAX_PROFILE_ID_BYTES: usize = 128;
const MAX_PRINCIPAL_ID_BYTES: usize = 128;
const MAX_CAPABILITIES: usize = 128;
const MAX_CERTIFICATE_DER_BYTES: usize = 16 * 1024;
const MAX_LAUNCH_TTL_MILLIS: u64 = 30_000;
/// Transport identifier reserved for inherited-channel bundled activation.
pub const PROTECTED_BUNDLED_TRANSPORT_PROFILE_ID: &str = "gocode-bundled-runtime/1";
/// Exact credential-free provider profile identity.
pub const DETERMINISTIC_PROVIDER_PROFILE_ID: &str = "gocode-deterministic-text/1";
/// Exact bounded OpenAI Responses text provider profile identity.
pub const OPENAI_RESPONSES_TEXT_PROVIDER_PROFILE_ID: &str = "gocode-openai-responses-text/1";
/// Exact bounded DeepSeek Responses text provider profile identity.
pub const DEEPSEEK_RESPONSES_TEXT_PROVIDER_PROFILE_ID: &str = "gocode-deepseek-responses-text/1";
/// Digest of the released deterministic text provider contract.
pub const DETERMINISTIC_PROVIDER_PROFILE_DIGEST: [u8; 32] = [
    0xb7, 0x9e, 0xfd, 0x52, 0xcd, 0x0d, 0xe3, 0x29, 0x17, 0x0e, 0xfa, 0xae, 0xd2, 0xa1, 0x8e, 0x6d,
    0x9f, 0xb0, 0xb9, 0xd7, 0x3d, 0x8b, 0x47, 0x40, 0x65, 0x14, 0x45, 0xb4, 0xe9, 0x0a, 0x95, 0x17,
];
/// Digest of the exact distributed OpenAI Responses text profile bytes.
pub const OPENAI_RESPONSES_TEXT_PROVIDER_PROFILE_DIGEST: [u8; 32] = [
    0xd3, 0xe2, 0x09, 0x34, 0x77, 0x5d, 0x9d, 0x97, 0x03, 0x50, 0xd1, 0x6b, 0x78, 0xa1, 0x73, 0x98,
    0x85, 0xc0, 0x8d, 0xd5, 0xd3, 0xe4, 0x7b, 0x93, 0x07, 0x23, 0x3d, 0x4d, 0xd0, 0xfb, 0xed, 0x80,
];
/// Digest of the exact distributed DeepSeek Responses text profile bytes.
pub const DEEPSEEK_RESPONSES_TEXT_PROVIDER_PROFILE_DIGEST: [u8; 32] = [
    0x01, 0x12, 0xc4, 0xb6, 0xce, 0x64, 0x73, 0x98, 0x10, 0xbb, 0x79, 0x80, 0x2e, 0xbb, 0x5a, 0xe6, 0xfd, 0x8a, 0xc5, 0x63, 0xd1, 0xd1, 0x39, 0x7a, 0xc5, 0x1f, 0x07, 0xa1, 0x90, 0x53, 0x81, 0x95,
];
/// Exact bounded Z.ai Coding Plan Chat Completions text profile identity.
pub const ZAI_CODING_CHAT_COMPLETIONS_TEXT_PROVIDER_PROFILE_ID: &str = "gocode-zai-coding-chat-completions-text/1";
/// Digest of the distributed Z.ai Coding Plan profile contract.
pub const ZAI_CODING_CHAT_COMPLETIONS_TEXT_PROVIDER_PROFILE_DIGEST: [u8; 32] = [
    0x81, 0xc9, 0xe5, 0x4d, 0x74, 0x86, 0xf2, 0x3e, 0x9a, 0x96, 0xa1, 0xfd, 0x9e, 0xb9, 0x62, 0x0e,
    0xe7, 0x77, 0xaf, 0xf8, 0xa1, 0xe3, 0xfc, 0x58, 0x15, 0x0c, 0x82, 0x45, 0x9b, 0xa8, 0x49, 0xde,
];
/// Exact bounded QwenCloud Token Plan Chat Completions text profile identity.
pub const QWENCLOUD_TOKEN_CHAT_COMPLETIONS_TEXT_PROVIDER_PROFILE_ID: &str = "gocode-qwencloud-token-chat-completions-text/1";
/// Digest of the distributed QwenCloud Token Plan profile contract.
pub const QWENCLOUD_TOKEN_CHAT_COMPLETIONS_TEXT_PROVIDER_PROFILE_DIGEST: [u8; 32] = [
    0xc9, 0x4c, 0xe8, 0x40, 0xb7, 0xbb, 0xbc, 0xda, 0x25, 0x10, 0x58, 0x77, 0x8b, 0x61, 0xaa, 0xe5,
    0xb4, 0xbf, 0xc9, 0x46, 0xa1, 0x6d, 0x7c, 0x35, 0x23, 0x2c, 0x09, 0x9d, 0xa7, 0xe2, 0x65, 0x9f,
];
/// Exact bounded Local Engine text provider profile identity.
pub const LOCAL_ENGINE_TEXT_PROVIDER_PROFILE_ID: &str = "gocode-local-engine-text/1";
/// Digest of the exact distributed Local Engine text profile bytes.
pub const LOCAL_ENGINE_TEXT_PROVIDER_PROFILE_DIGEST: [u8; 32] = [
    0xc6, 0x71, 0x84, 0x44, 0x6e, 0xfa, 0xd9, 0xf1, 0x37, 0x0a, 0x7d, 0x4d, 0x4d, 0xb1, 0x33, 0x3f,
    0xb2, 0x88, 0x2f, 0xf3, 0x76, 0x7c, 0x4b, 0x8d, 0xf1, 0xe3, 0x41, 0x3f, 0xe9, 0xae, 0x7f, 0x61,
];
const EXTERNAL_TRANSPORT_PROFILE_ID: &str = "gocode-local-runtime/2";
const KEY_DERIVATION_DOMAIN: &[u8] = b"gocode/bundled-launch/key-derivation/v1\0";
const BOOTSTRAP_DOMAIN: &[u8] = b"gocode/bundled-launch/bootstrap/v1";
const READINESS_DOMAIN: &[u8] = b"gocode/bundled-launch/readiness/v1";
const RENEW_DOMAIN: &[u8] = b"gocode/bundled-launch/renew/v1";
const SHUTDOWN_DOMAIN: &[u8] = b"gocode/bundled-launch/shutdown/v1";
const FIRST_ACTIVATION_PREPARE_DOMAIN: &[u8] = b"gocode/bundled-launch/first-activation-prepare/v1";
const FIRST_ACTIVATION_COMMIT_DOMAIN: &[u8] = b"gocode/bundled-launch/first-activation-commit/v1";
const READINESS_DOMAIN_V2: &[u8] = b"gocode/bundled-launch/readiness/v2";
const RENEW_DOMAIN_V2: &[u8] = b"gocode/bundled-launch/renew/v2";
const SHUTDOWN_DOMAIN_V2: &[u8] = b"gocode/bundled-launch/shutdown/v2";
const READINESS_DOMAIN_V3: &[u8] = b"gocode/credential-enrollment-launch/readiness/v3";
const RENEW_DOMAIN_V3: &[u8] = b"gocode/credential-enrollment-launch/renew/v3";
const SHUTDOWN_DOMAIN_V3: &[u8] = b"gocode/credential-enrollment-launch/shutdown/v3";
const ENROLLMENT_REQUEST_BINDING_DOMAIN_V3: &[u8] =
    b"gocode/credential-enrollment-launch/request-binding/v3\0";

type HmacSha256 = Hmac<Sha256>;

/// Closed protected-activation failure vocabulary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LaunchAuthorityError {
    MissingLaunchAuthority,
    StaleLaunchAuthority,
    ReusedLaunchAuthority,
    MissingExpectedStableBinding,
    UnexpectedExistingEventLog,
    FirstActivationPreparationMismatch,
    FirstActivationCommitIncomplete,
    ExecutableIdentityMismatch,
    ProfileHashMismatch,
    InstanceGenerationSessionMismatch,
    DowngradedExternalProfile,
    UnsupportedPlatformBackend,
    ProtectedChannelUnavailable,
    ReadinessTimeout,
    ReadinessProofMismatch,
    RenewalReplay,
    RenewalUnavailable,
    OwnershipMismatch,
    MissingProviderBinding,
    ProviderModeMismatch,
    ProviderProfileMismatch,
    InvalidContract,
}

impl fmt::Display for LaunchAuthorityError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::MissingLaunchAuthority => "missing_launch_authority",
            Self::StaleLaunchAuthority => "stale_launch_authority",
            Self::ReusedLaunchAuthority => "reused_launch_authority",
            Self::MissingExpectedStableBinding => "missing_expected_stable_binding",
            Self::UnexpectedExistingEventLog => "unexpected_existing_event_log",
            Self::FirstActivationPreparationMismatch => "first_activation_preparation_mismatch",
            Self::FirstActivationCommitIncomplete => "first_activation_commit_incomplete",
            Self::ExecutableIdentityMismatch => "executable_identity_mismatch",
            Self::ProfileHashMismatch => "profile_hash_mismatch",
            Self::InstanceGenerationSessionMismatch => "instance_generation_session_mismatch",
            Self::DowngradedExternalProfile => "downgraded_external_profile",
            Self::UnsupportedPlatformBackend => "unsupported_platform_backend",
            Self::ProtectedChannelUnavailable => "protected_channel_unavailable",
            Self::ReadinessTimeout => "readiness_timeout",
            Self::ReadinessProofMismatch => "readiness_proof_mismatch",
            Self::RenewalReplay => "renewal_replay",
            Self::RenewalUnavailable => "renewal_unavailable",
            Self::OwnershipMismatch => "ownership_mismatch",
            Self::MissingProviderBinding => "missing_provider_binding",
            Self::ProviderModeMismatch => "provider_mode_mismatch",
            Self::ProviderProfileMismatch => "provider_profile_mismatch",
            Self::InvalidContract => "invalid_contract",
        })
    }
}

impl std::error::Error for LaunchAuthorityError {}

/// A one-launch memory-only secret transported only over the inherited channel.
#[derive(Clone)]
pub struct LaunchSecret(Zeroizing<[u8; 32]>);

impl LaunchSecret {
    /// Creates a non-zero launch secret.
    pub fn from_bytes(bytes: [u8; 32]) -> Result<Self, LaunchAuthorityError> {
        if bytes == [0; 32] {
            return Err(LaunchAuthorityError::MissingLaunchAuthority);
        }
        Ok(Self(Zeroizing::new(bytes)))
    }

    /// Derives role-separated keys without exposing the raw secret.
    #[must_use]
    pub fn derive_keys(&self) -> ProtectedActivationKeys {
        ProtectedActivationKeys {
            bootstrap: Zeroizing::new(derive_key(&self.0, BOOTSTRAP_DOMAIN)),
            readiness: Zeroizing::new(derive_key(&self.0, READINESS_DOMAIN)),
            renewal: Zeroizing::new(derive_key(&self.0, RENEW_DOMAIN)),
            shutdown: Zeroizing::new(derive_key(&self.0, SHUTDOWN_DOMAIN)),
            native_key_epoch: 1,
        }
    }

    fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl PartialEq for LaunchSecret {
    fn eq(&self, other: &Self) -> bool {
        bool::from(self.0.as_ref().ct_eq(other.0.as_ref()))
    }
}

impl Eq for LaunchSecret {}

/// Role-separated activation keys retained only by native desktop and daemon.
#[derive(Clone)]
pub struct ProtectedActivationKeys {
    bootstrap: Zeroizing<[u8; 32]>,
    readiness: Zeroizing<[u8; 32]>,
    renewal: Zeroizing<[u8; 32]>,
    shutdown: Zeroizing<[u8; 32]>,
    native_key_epoch: u64,
}

/// Raw activation-key copies exposed only to test-support leak audits.
///
/// The production build does not contain this type or its constructor.
#[cfg(feature = "test-support")]
pub struct ProtectedActivationKeyMaterialForTest {
    bootstrap: Zeroizing<[u8; 32]>,
    readiness: Zeroizing<[u8; 32]>,
    renewal: Zeroizing<[u8; 32]>,
    shutdown: Zeroizing<[u8; 32]>,
}

#[cfg(feature = "test-support")]
impl ProtectedActivationKeyMaterialForTest {
    #[doc(hidden)]
    #[must_use]
    pub fn into_values(self) -> [Zeroizing<[u8; 32]>; 4] {
        [self.bootstrap, self.readiness, self.renewal, self.shutdown]
    }
}

impl ProtectedActivationKeys {
    /// Advances a replacement key set after verified readiness; renewals retain this key set.
    pub fn advance_native_key_epoch_from(
        &mut self,
        previous: &Self,
    ) -> Result<(), LaunchAuthorityError> {
        self.native_key_epoch = previous
            .native_key_epoch
            .checked_add(1)
            .ok_or(LaunchAuthorityError::InvalidContract)?;
        Ok(())
    }

    /// Copies the one-time HTTP bootstrap key into another zeroizing owner.
    #[must_use]
    pub fn bootstrap_key(&self) -> Zeroizing<[u8; 32]> {
        Zeroizing::new(*self.bootstrap)
    }

    /// Zeroizes the launch-only HTTP bootstrap key after the one-time native
    /// profile has taken ownership of its copy.
    pub fn forget_bootstrap_key(&mut self) {
        self.bootstrap.zeroize();
    }

    fn readiness_key(&self) -> &[u8; 32] {
        &self.readiness
    }

    /// Builds a fixed-purpose private capability for the permission ceremony.
    #[must_use]
    pub fn permission_control_native_authenticator(
        &self,
    ) -> permission_control_v1::PermissionControlNativeAuthenticatorV1 {
        permission_control_v1::PermissionControlNativeAuthenticatorV1::from_readiness_key(
            self.readiness_key(),
            self.native_key_epoch,
        )
    }

    fn renewal_key_ref(&self) -> &[u8; 32] {
        &self.renewal
    }

    fn shutdown_key_ref(&self) -> &[u8; 32] {
        &self.shutdown
    }

    /// Copies the protected renewal key for the owned control-channel endpoint.
    #[must_use]
    pub fn renewal_key(&self) -> Zeroizing<[u8; 32]> {
        Zeroizing::new(*self.renewal)
    }

    /// Copies the protected shutdown key for the owned control-channel endpoint.
    #[must_use]
    pub fn shutdown_key(&self) -> Zeroizing<[u8; 32]> {
        Zeroizing::new(*self.shutdown)
    }

    /// Copies every role-separated key for test-only forbidden-sink audits.
    #[cfg(feature = "test-support")]
    #[doc(hidden)]
    #[must_use]
    pub fn test_material(&self) -> ProtectedActivationKeyMaterialForTest {
        ProtectedActivationKeyMaterialForTest {
            bootstrap: Zeroizing::new(*self.bootstrap),
            readiness: Zeroizing::new(*self.readiness),
            renewal: Zeroizing::new(*self.renewal),
            shutdown: Zeroizing::new(*self.shutdown),
        }
    }
}

/// Exact digest identity of the executable which is about to run.
#[derive(Clone, Eq, PartialEq)]
pub struct ExecutableIdentityV1 {
    executable_sha256: [u8; 32],
    canonical_path_sha256: [u8; 32],
    byte_length: u64,
}
