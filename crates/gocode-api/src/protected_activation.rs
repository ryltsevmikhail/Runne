//! Protected bundled-runtime activation wire and binding contracts.

use std::fmt;
use std::path::PathBuf;

use gocode_domain::id::validate_uuid_v7_bytes;
use gocode_plugin_protocol::cbor::{
    CborDecoder, CborEncoder, DecodeError, DeterministicCodec, EncodeError,
};
use gocode_plugin_protocol::frame::{FrameLimits, decode_codec_frame, encode_codec_frame};
use gocode_plugin_protocol::profile::DecodeLimits;
use hmac::{Hmac, Mac};
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

impl ExecutableIdentityV1 {
    /// Creates a non-empty executable identity.
    pub fn new(
        executable_sha256: [u8; 32],
        canonical_path_sha256: [u8; 32],
        byte_length: u64,
    ) -> Result<Self, LaunchAuthorityError> {
        if executable_sha256 == [0; 32] || canonical_path_sha256 == [0; 32] || byte_length == 0 {
            return Err(LaunchAuthorityError::ExecutableIdentityMismatch);
        }
        Ok(Self {
            executable_sha256,
            canonical_path_sha256,
            byte_length,
        })
    }

    /// Measures an absolute regular executable through an opened file handle.
    pub fn measure(path: &std::path::Path) -> Result<Self, LaunchAuthorityError> {
        use std::io::Read as _;

        let canonical = std::fs::canonicalize(path)
            .map_err(|_| LaunchAuthorityError::ExecutableIdentityMismatch)?;
        if !canonical.is_absolute() {
            return Err(LaunchAuthorityError::ExecutableIdentityMismatch);
        }
        let mut file = std::fs::File::open(&canonical)
            .map_err(|_| LaunchAuthorityError::ExecutableIdentityMismatch)?;
        let metadata = file
            .metadata()
            .map_err(|_| LaunchAuthorityError::ExecutableIdentityMismatch)?;
        if !metadata.is_file() || metadata.len() == 0 {
            return Err(LaunchAuthorityError::ExecutableIdentityMismatch);
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            if metadata.permissions().mode() & 0o111 == 0 {
                return Err(LaunchAuthorityError::ExecutableIdentityMismatch);
            }
        }
        let mut executable_hasher = Sha256::new();
        let mut buffer = [0; 64 * 1024];
        loop {
            let read = file
                .read(&mut buffer)
                .map_err(|_| LaunchAuthorityError::ExecutableIdentityMismatch)?;
            if read == 0 {
                break;
            }
            executable_hasher.update(&buffer[..read]);
        }
        let executable_sha256 = executable_hasher.finalize().into();
        let canonical_path_sha256 = hash_canonical_path(&canonical);
        Self::new(executable_sha256, canonical_path_sha256, metadata.len())
    }

    pub const fn executable_sha256(&self) -> &[u8; 32] {
        &self.executable_sha256
    }

    pub const fn canonical_path_sha256(&self) -> &[u8; 32] {
        &self.canonical_path_sha256
    }

    pub const fn byte_length(&self) -> u64 {
        self.byte_length
    }
}

#[cfg(unix)]
fn hash_canonical_path(path: &std::path::Path) -> [u8; 32] {
    use std::os::unix::ffi::OsStrExt as _;
    Sha256::digest(path.as_os_str().as_bytes()).into()
}

#[cfg(windows)]
fn hash_canonical_path(path: &std::path::Path) -> [u8; 32] {
    use std::os::windows::ffi::OsStrExt as _;
    let mut hasher = Sha256::new();
    for unit in path.as_os_str().encode_wide() {
        hasher.update(unit.to_le_bytes());
    }
    hasher.finalize().into()
}

#[cfg(not(any(unix, windows)))]
fn hash_canonical_path(path: &std::path::Path) -> [u8; 32] {
    Sha256::digest(path.to_string_lossy().as_bytes()).into()
}

impl fmt::Debug for ExecutableIdentityV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ExecutableIdentityV1")
            .field("byte_length", &self.byte_length)
            .finish_non_exhaustive()
    }
}

/// Expected protected transport/profile contract.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProtectedRuntimeProfileV1 {
    transport_profile_id: String,
    runtime_profile_schema_version: u32,
    profile_id: String,
    profile_hash: [u8; 32],
    capability_digest: [u8; 32],
}

impl ProtectedRuntimeProfileV1 {
    /// Creates a bounded profile expectation.
    pub fn new(
        transport_profile_id: impl Into<String>,
        runtime_profile_schema_version: u32,
        profile_id: impl Into<String>,
        profile_hash: [u8; 32],
        capability_digest: [u8; 32],
    ) -> Result<Self, LaunchAuthorityError> {
        let transport_profile_id = transport_profile_id.into();
        let profile_id = profile_id.into();
        if !valid_text(&transport_profile_id, MAX_PROFILE_ID_BYTES)
            || !valid_text(&profile_id, MAX_PROFILE_ID_BYTES)
            || runtime_profile_schema_version == 0
            || profile_hash == [0; 32]
            || capability_digest == [0; 32]
        {
            return Err(LaunchAuthorityError::InvalidContract);
        }
        Ok(Self {
            transport_profile_id,
            runtime_profile_schema_version,
            profile_id,
            profile_hash,
            capability_digest,
        })
    }

    pub fn transport_profile_id(&self) -> &str {
        &self.transport_profile_id
    }

    pub const fn runtime_profile_schema_version(&self) -> u32 {
        self.runtime_profile_schema_version
    }

    pub fn profile_id(&self) -> &str {
        &self.profile_id
    }

    pub const fn profile_hash(&self) -> &[u8; 32] {
        &self.profile_hash
    }

    pub const fn capability_digest(&self) -> &[u8; 32] {
        &self.capability_digest
    }
}

/// Exact daemon provider activation mode.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProviderActivationModeV1 {
    /// Credential-free deterministic compatibility provider.
    DeterministicV1,
    /// Exact bounded OpenAI Responses text provider.
    OpenAiResponsesTextV1,
}

impl ProviderActivationModeV1 {
    /// Returns the stable public mode identifier.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::DeterministicV1 => "deterministic_v1",
            Self::OpenAiResponsesTextV1 => "openai_responses_text_v1",
        }
    }

    const fn wire_code(self) -> u64 {
        match self {
            Self::DeterministicV1 => 1,
            Self::OpenAiResponsesTextV1 => 2,
        }
    }

    fn from_wire_code(code: u64) -> Result<Self, DecodeError> {
        match code {
            1 => Ok(Self::DeterministicV1),
            2 => Ok(Self::OpenAiResponsesTextV1),
            key => Err(DecodeError::UnknownField { key }),
        }
    }
}

impl TryFrom<&str> for ProviderActivationModeV1 {
    type Error = LaunchAuthorityError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        match value {
            "deterministic_v1" => Ok(Self::DeterministicV1),
            "openai_responses_text_v1" => Ok(Self::OpenAiResponsesTextV1),
            _ => Err(LaunchAuthorityError::ProviderModeMismatch),
        }
    }
}

/// Exact non-secret provider mode/profile tuple authenticated by protocol V2.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProviderActivationBindingV1 {
    mode: ProviderActivationModeV1,
    profile_id: String,
    profile_digest: [u8; 32],
}

impl ProviderActivationBindingV1 {
    /// Creates a bounded exact provider activation binding.
    pub fn new(
        mode: ProviderActivationModeV1,
        profile_id: impl Into<String>,
        profile_digest: [u8; 32],
    ) -> Result<Self, LaunchAuthorityError> {
        let profile_id = profile_id.into();
        let expected = match mode {
            ProviderActivationModeV1::DeterministicV1 => (
                DETERMINISTIC_PROVIDER_PROFILE_ID,
                DETERMINISTIC_PROVIDER_PROFILE_DIGEST,
            ),
            ProviderActivationModeV1::OpenAiResponsesTextV1 => (
                OPENAI_RESPONSES_TEXT_PROVIDER_PROFILE_ID,
                OPENAI_RESPONSES_TEXT_PROVIDER_PROFILE_DIGEST,
            ),
        };
        if !valid_text(&profile_id, MAX_PROFILE_ID_BYTES)
            || profile_id != expected.0
            || profile_digest != expected.1
        {
            return Err(LaunchAuthorityError::ProviderProfileMismatch);
        }
        Ok(Self {
            mode,
            profile_id,
            profile_digest,
        })
    }

    /// Returns the released deterministic provider binding.
    #[must_use]
    pub fn deterministic_v1() -> Self {
        Self {
            mode: ProviderActivationModeV1::DeterministicV1,
            profile_id: DETERMINISTIC_PROVIDER_PROFILE_ID.to_owned(),
            profile_digest: DETERMINISTIC_PROVIDER_PROFILE_DIGEST,
        }
    }

    /// Returns the released exact OpenAI Responses text provider binding.
    #[must_use]
    pub fn openai_responses_text_v1() -> Self {
        Self {
            mode: ProviderActivationModeV1::OpenAiResponsesTextV1,
            profile_id: OPENAI_RESPONSES_TEXT_PROVIDER_PROFILE_ID.to_owned(),
            profile_digest: OPENAI_RESPONSES_TEXT_PROVIDER_PROFILE_DIGEST,
        }
    }

    /// Returns the exact activation mode.
    #[must_use]
    pub const fn mode(&self) -> ProviderActivationModeV1 {
        self.mode
    }

    /// Returns the exact immutable provider profile identifier.
    #[must_use]
    pub fn profile_id(&self) -> &str {
        &self.profile_id
    }

    /// Returns the exact immutable provider profile digest.
    #[must_use]
    pub const fn profile_digest(&self) -> &[u8; 32] {
        &self.profile_digest
    }

    fn verify_exact(&self, expected: &Self) -> Result<(), LaunchAuthorityError> {
        if self.mode != expected.mode {
            return Err(LaunchAuthorityError::ProviderModeMismatch);
        }
        if self.profile_id != expected.profile_id || self.profile_digest != expected.profile_digest
        {
            return Err(LaunchAuthorityError::ProviderProfileMismatch);
        }
        Ok(())
    }
}

/// Stable runtime identity expected across daemon restarts.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StableRuntimeBindingV1 {
    authority_id: [u8; 16],
    principal_id: String,
    lineage_id: [u8; 16],
    profile_id: String,
    profile_hash: [u8; 32],
    capability_digest: [u8; 32],
}

impl StableRuntimeBindingV1 {
    /// Creates a validated stable runtime binding.
    pub fn new(
        authority_id: [u8; 16],
        principal_id: impl Into<String>,
        lineage_id: [u8; 16],
        profile_id: impl Into<String>,
        profile_hash: [u8; 32],
        capability_digest: [u8; 32],
    ) -> Result<Self, LaunchAuthorityError> {
        let principal_id = principal_id.into();
        let profile_id = profile_id.into();
        if validate_uuid_v7_bytes(&authority_id).is_err()
            || validate_uuid_v7_bytes(&lineage_id).is_err()
            || !valid_text(&principal_id, MAX_PRINCIPAL_ID_BYTES)
            || !valid_text(&profile_id, MAX_PROFILE_ID_BYTES)
            || profile_hash == [0; 32]
            || capability_digest == [0; 32]
        {
            return Err(LaunchAuthorityError::InvalidContract);
        }
        Ok(Self {
            authority_id,
            principal_id,
            lineage_id,
            profile_id,
            profile_hash,
            capability_digest,
        })
    }

    pub const fn authority_id(&self) -> &[u8; 16] {
        &self.authority_id
    }

    pub fn principal_id(&self) -> &str {
        &self.principal_id
    }

    pub const fn lineage_id(&self) -> &[u8; 16] {
        &self.lineage_id
    }

    pub fn profile_id(&self) -> &str {
        &self.profile_id
    }

    pub const fn profile_hash(&self) -> &[u8; 32] {
        &self.profile_hash
    }

    pub const fn capability_digest(&self) -> &[u8; 32] {
        &self.capability_digest
    }
}

/// Durable, non-secret recovery record for an interrupted first activation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PendingFirstActivationV1 {
    preparation_id: [u8; 16],
    runtime_root_identity: [u8; 32],
    stable: StableRuntimeBindingV1,
    executable: ExecutableIdentityV1,
    profile: ProtectedRuntimeProfileV1,
}

impl PendingFirstActivationV1 {
    /// Creates an exact first-activation recovery record.
    pub fn new(
        preparation_id: [u8; 16],
        runtime_root_identity: [u8; 32],
        stable: StableRuntimeBindingV1,
        executable: ExecutableIdentityV1,
        profile: ProtectedRuntimeProfileV1,
    ) -> Result<Self, LaunchAuthorityError> {
        if validate_uuid_v7_bytes(&preparation_id).is_err() || runtime_root_identity == [0; 32] {
            return Err(LaunchAuthorityError::FirstActivationPreparationMismatch);
        }
        Ok(Self {
            preparation_id,
            runtime_root_identity,
            stable,
            executable,
            profile,
        })
    }

    pub const fn preparation_id(&self) -> &[u8; 16] {
        &self.preparation_id
    }

    pub const fn runtime_root_identity(&self) -> &[u8; 32] {
        &self.runtime_root_identity
    }

    pub const fn stable(&self) -> &StableRuntimeBindingV1 {
        &self.stable
    }

    pub const fn executable(&self) -> &ExecutableIdentityV1 {
        &self.executable
    }

    pub const fn profile(&self) -> &ProtectedRuntimeProfileV1 {
        &self.profile
    }
}

/// Stable-profile admission mode for one protected launch.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ActivationDispositionV1 {
    FirstActivation,
    Existing(Box<StableRuntimeBindingV1>),
    ResumeFirstActivation(Box<PendingFirstActivationV1>),
}

impl ActivationDispositionV1 {
    fn expected_stable(&self) -> Option<&StableRuntimeBindingV1> {
        match self {
            Self::FirstActivation => None,
            Self::Existing(stable) => Some(stable.as_ref()),
            Self::ResumeFirstActivation(pending) => Some(pending.stable()),
        }
    }
}

/// Exact non-secret values the daemon must match before consuming authority.
pub struct LaunchAuthorityValidationV1<'a> {
    pub principal_id: &'a str,
    pub profile: &'a ProtectedRuntimeProfileV1,
    pub executable: &'a ExecutableIdentityV1,
}

/// Protected launch request sent once over the inherited channel.
#[derive(Clone, Eq, PartialEq)]
pub struct ProtectedLaunchRequestV1 {
    protocol_schema_version: u32,
    launch_authority_id: [u8; 16],
    desktop_host_instance_id: [u8; 16],
    launch_secret: LaunchSecret,
    issued_at_unix_millis: u64,
    expires_at_unix_millis: u64,
    principal_id: String,
    profile: ProtectedRuntimeProfileV1,
    executable: ExecutableIdentityV1,
    runtime_root: PathBuf,
    activation_disposition: ActivationDispositionV1,
}

impl ProtectedLaunchRequestV1 {
    /// Builds a bounded one-time launch request.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        launch_authority_id: [u8; 16],
        desktop_host_instance_id: [u8; 16],
        launch_secret: LaunchSecret,
        issued_at_unix_millis: u64,
        expires_at_unix_millis: u64,
        principal_id: impl Into<String>,
        profile: ProtectedRuntimeProfileV1,
        executable: ExecutableIdentityV1,
        runtime_root: PathBuf,
        activation_disposition: ActivationDispositionV1,
    ) -> Result<Self, LaunchAuthorityError> {
        let principal_id = principal_id.into();
        let root_text = runtime_root
            .to_str()
            .ok_or(LaunchAuthorityError::InvalidContract)?;
        if validate_uuid_v7_bytes(&launch_authority_id).is_err()
            || validate_uuid_v7_bytes(&desktop_host_instance_id).is_err()
            || !valid_text(&principal_id, MAX_PRINCIPAL_ID_BYTES)
            || !runtime_root.is_absolute()
            || !valid_text(root_text, MAX_TEXT_BYTES)
            || issued_at_unix_millis >= expires_at_unix_millis
            || expires_at_unix_millis.saturating_sub(issued_at_unix_millis) > MAX_LAUNCH_TTL_MILLIS
        {
            return Err(LaunchAuthorityError::InvalidContract);
        }
        Ok(Self {
            protocol_schema_version: PROTOCOL_SCHEMA_VERSION,
            launch_authority_id,
            desktop_host_instance_id,
            launch_secret,
            issued_at_unix_millis,
            expires_at_unix_millis,
            principal_id,
            profile,
            executable,
            runtime_root,
            activation_disposition,
        })
    }

    /// Validates TTL and all caller-pinned non-secret launch values.
    pub fn validate(
        &self,
        now_unix_millis: u64,
        expected: &LaunchAuthorityValidationV1<'_>,
    ) -> Result<(), LaunchAuthorityError> {
        self.validate_freshness(now_unix_millis)?;
        if self.profile.transport_profile_id == EXTERNAL_TRANSPORT_PROFILE_ID
            || expected.profile.transport_profile_id == EXTERNAL_TRANSPORT_PROFILE_ID
            || self.profile.transport_profile_id != PROTECTED_BUNDLED_TRANSPORT_PROFILE_ID
            || expected.profile.transport_profile_id != PROTECTED_BUNDLED_TRANSPORT_PROFILE_ID
        {
            return Err(LaunchAuthorityError::DowngradedExternalProfile);
        }
        if self.principal_id != expected.principal_id {
            return Err(LaunchAuthorityError::MissingLaunchAuthority);
        }
        if self.executable != *expected.executable {
            return Err(LaunchAuthorityError::ExecutableIdentityMismatch);
        }
        if self.profile.profile_hash != expected.profile.profile_hash
            || self.profile.profile_id != expected.profile.profile_id
            || self.profile.runtime_profile_schema_version
                != expected.profile.runtime_profile_schema_version
            || self.profile.capability_digest != expected.profile.capability_digest
        {
            return Err(LaunchAuthorityError::ProfileHashMismatch);
        }
        Ok(())
    }

    /// Enforces the reader-only V1 compatibility boundary.
    ///
    /// V1 has no authenticated provider binding and therefore can activate
    /// only the credential-free deterministic provider. OpenAI activation must
    /// use [`ProtectedLaunchRequestV2`].
    pub const fn validate_provider_mode(
        &self,
        mode: ProviderActivationModeV1,
    ) -> Result<(), LaunchAuthorityError> {
        match mode {
            ProviderActivationModeV1::DeterministicV1 => Ok(()),
            ProviderActivationModeV1::OpenAiResponsesTextV1 => {
                Err(LaunchAuthorityError::MissingProviderBinding)
            }
        }
    }

    /// Rechecks the signed launch-authority deadline immediately before use.
    pub fn validate_freshness(&self, now_unix_millis: u64) -> Result<(), LaunchAuthorityError> {
        if self.protocol_schema_version != PROTOCOL_SCHEMA_VERSION
            || now_unix_millis < self.issued_at_unix_millis
            || now_unix_millis > self.expires_at_unix_millis
        {
            return Err(LaunchAuthorityError::StaleLaunchAuthority);
        }
        Ok(())
    }

    /// Encodes the exact deterministic bounded launch frame.
    pub fn encode_frame(&self) -> Result<Vec<u8>, EncodeError> {
        encode_codec_frame(
            self,
            &FrameLimits {
                max_frame_bytes: MAX_FRAME_BYTES,
            },
        )
    }

    /// Decodes one exact deterministic bounded launch frame.
    pub fn decode_frame(frame: &[u8]) -> Result<Self, DecodeError> {
        decode_codec_frame(frame, &decode_limits())
    }

    pub const fn launch_authority_id(&self) -> [u8; 16] {
        self.launch_authority_id
    }

    pub const fn expires_at_unix_millis(&self) -> u64 {
        self.expires_at_unix_millis
    }

    pub const fn desktop_host_instance_id(&self) -> [u8; 16] {
        self.desktop_host_instance_id
    }

    pub fn principal_id(&self) -> &str {
        &self.principal_id
    }

    pub const fn profile(&self) -> &ProtectedRuntimeProfileV1 {
        &self.profile
    }

    pub const fn executable(&self) -> &ExecutableIdentityV1 {
        &self.executable
    }

    pub fn runtime_root(&self) -> &std::path::Path {
        &self.runtime_root
    }

    pub const fn activation_disposition(&self) -> &ActivationDispositionV1 {
        &self.activation_disposition
    }

    /// Derives the native-only launch keys.
    #[must_use]
    pub fn derive_keys(&self) -> ProtectedActivationKeys {
        self.launch_secret.derive_keys()
    }

    /// Derives native-only keys and immediately zeroizes the raw launch secret.
    pub fn derive_keys_and_forget(&mut self) -> ProtectedActivationKeys {
        let keys = self.launch_secret.derive_keys();
        self.launch_secret.0.zeroize();
        keys
    }
}

impl fmt::Debug for ProtectedLaunchRequestV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProtectedLaunchRequestV1")
            .field("protocol_schema_version", &self.protocol_schema_version)
            .field("activation_disposition", &self.activation_disposition)
            .field("protected_fields", &"<redacted>")
            .finish()
    }
}

impl DeterministicCodec for ProtectedLaunchRequestV1 {
    const MESSAGE_TYPE_ID: u32 = 1;

    fn encode(&self, encoder: &mut CborEncoder) -> Result<(), EncodeError> {
        encoder.write_map_header(12);
        write_key(encoder, 0);
        encoder.write_unsigned(u64::from(Self::MESSAGE_TYPE_ID));
        write_key(encoder, 1);
        encoder.write_unsigned(u64::from(self.protocol_schema_version));
        write_key(encoder, 2);
        encoder.write_byte_string(&self.launch_authority_id);
        write_key(encoder, 3);
        encoder.write_byte_string(&self.desktop_host_instance_id);
        write_key(encoder, 4);
        encoder.write_byte_string(self.launch_secret.as_bytes());
        write_key(encoder, 5);
        encoder.write_unsigned(self.issued_at_unix_millis);
        write_key(encoder, 6);
        encoder.write_unsigned(self.expires_at_unix_millis);
        write_key(encoder, 7);
        encoder.write_text_string(&self.principal_id);
        write_key(encoder, 8);
        encode_profile(encoder, &self.profile);
        write_key(encoder, 9);
        encode_executable(encoder, &self.executable);
        write_key(encoder, 10);
        encoder.write_text_string(
            self.runtime_root
                .to_str()
                .expect("validated UTF-8 runtime root"),
        );
        write_key(encoder, 11);
        encode_disposition(encoder, &self.activation_disposition);
        Ok(())
    }

    fn decode(type_id: u32, decoder: &mut CborDecoder<'_>) -> Result<Self, DecodeError> {
        if type_id != Self::MESSAGE_TYPE_ID || decoder.read_map_header(12)? != 12 {
            return Err(DecodeError::UnknownMessageType { type_id });
        }
        expect_key(decoder, 0)?;
        expect_message_type(decoder, Self::MESSAGE_TYPE_ID)?;
        expect_key(decoder, 1)?;
        let schema = decoder.read_unsigned(u64::from(u32::MAX))?;
        if schema != u64::from(PROTOCOL_SCHEMA_VERSION) {
            return Err(DecodeError::UnknownField { key: 1 });
        }
        expect_key(decoder, 2)?;
        let launch_authority_id = decode_fixed::<16>(decoder)?;
        expect_key(decoder, 3)?;
        let desktop_host_instance_id = decode_fixed::<16>(decoder)?;
        expect_key(decoder, 4)?;
        let launch_secret = LaunchSecret::from_bytes(decode_fixed::<32>(decoder)?)
            .map_err(|_| DecodeError::UnknownField { key: 4 })?;
        expect_key(decoder, 5)?;
        let issued_at_unix_millis = decoder.read_unsigned(u64::MAX)?;
        expect_key(decoder, 6)?;
        let expires_at_unix_millis = decoder.read_unsigned(u64::MAX)?;
        expect_key(decoder, 7)?;
        let principal_id = decoder.read_text_string(MAX_PRINCIPAL_ID_BYTES)?.to_owned();
        expect_key(decoder, 8)?;
        let profile = decode_profile(decoder)?;
        expect_key(decoder, 9)?;
        let executable = decode_executable(decoder)?;
        expect_key(decoder, 10)?;
        let runtime_root = PathBuf::from(decoder.read_text_string(MAX_TEXT_BYTES)?);
        expect_key(decoder, 11)?;
        let activation_disposition = decode_disposition(decoder)?;
        Self::new(
            launch_authority_id,
            desktop_host_instance_id,
            launch_secret,
            issued_at_unix_millis,
            expires_at_unix_millis,
            principal_id,
            profile,
            executable,
            runtime_root,
            activation_disposition,
        )
        .map_err(|_| DecodeError::UnknownField { key: 11 })
    }
}

/// Runtime-prepared non-secret first-activation record with exact HMAC proof.
#[derive(Clone, Eq, PartialEq)]
pub struct ProtectedFirstActivationPreparedV1 {
    protocol_schema_version: u32,
    launch_authority_id: [u8; 16],
    desktop_host_instance_id: [u8; 16],
    pending: PendingFirstActivationV1,
    proof: [u8; 32],
}

impl ProtectedFirstActivationPreparedV1 {
    /// Builds an unsigned prepared response.
    #[must_use]
    pub const fn new(
        launch_authority_id: [u8; 16],
        desktop_host_instance_id: [u8; 16],
        pending: PendingFirstActivationV1,
    ) -> Self {
        Self {
            protocol_schema_version: PROTOCOL_SCHEMA_VERSION,
            launch_authority_id,
            desktop_host_instance_id,
            pending,
            proof: [0; 32],
        }
    }

    /// Signs the exact canonical prepare transcript.
    pub fn sign(&mut self, keys: &ProtectedActivationKeys) {
        self.proof = authenticated_mac(
            keys.readiness_key(),
            FIRST_ACTIVATION_PREPARE_DOMAIN,
            &self.unsigned_payload(),
        );
    }

    /// Verifies request binding, prepared identity, and HMAC.
    pub fn verify_exact(
        &self,
        request: &ProtectedLaunchRequestV1,
        keys: &ProtectedActivationKeys,
    ) -> Result<(), LaunchAuthorityError> {
        if self.launch_authority_id != request.launch_authority_id
            || self.desktop_host_instance_id != request.desktop_host_instance_id
        {
            return Err(LaunchAuthorityError::MissingLaunchAuthority);
        }
        if self.pending.executable != request.executable || self.pending.profile != request.profile
        {
            return Err(LaunchAuthorityError::FirstActivationPreparationMismatch);
        }
        match request.activation_disposition() {
            ActivationDispositionV1::FirstActivation => {}
            ActivationDispositionV1::ResumeFirstActivation(expected)
                if expected.as_ref() == &self.pending => {}
            _ => return Err(LaunchAuthorityError::FirstActivationPreparationMismatch),
        }
        let expected = authenticated_mac(
            keys.readiness_key(),
            FIRST_ACTIVATION_PREPARE_DOMAIN,
            &self.unsigned_payload(),
        );
        if !bool::from(expected.ct_eq(&self.proof)) {
            return Err(LaunchAuthorityError::ReadinessProofMismatch);
        }
        Ok(())
    }

    /// Returns the durable non-secret record after proof verification.
    pub const fn pending(&self) -> &PendingFirstActivationV1 {
        &self.pending
    }

    /// Encodes the deterministic bounded prepare frame.
    pub fn encode_frame(&self) -> Result<Vec<u8>, EncodeError> {
        encode_codec_frame(
            self,
            &FrameLimits {
                max_frame_bytes: MAX_FRAME_BYTES,
            },
        )
    }

    /// Decodes one deterministic bounded prepare frame.
    pub fn decode_frame(frame: &[u8]) -> Result<Self, DecodeError> {
        decode_codec_frame(frame, &decode_limits())
    }

    fn unsigned_payload(&self) -> Vec<u8> {
        let mut encoder = CborEncoder::new();
        self.encode_fields(&mut encoder, false);
        encoder.into_bytes()
    }

    fn encode_fields(&self, encoder: &mut CborEncoder, include_proof: bool) {
        encoder.write_map_header(if include_proof { 6 } else { 5 });
        write_key(encoder, 0);
        encoder.write_unsigned(u64::from(Self::MESSAGE_TYPE_ID));
        write_key(encoder, 1);
        encoder.write_unsigned(u64::from(self.protocol_schema_version));
        write_key(encoder, 2);
        encoder.write_byte_string(&self.launch_authority_id);
        write_key(encoder, 3);
        encoder.write_byte_string(&self.desktop_host_instance_id);
        write_key(encoder, 4);
        encode_pending(encoder, &self.pending);
        if include_proof {
            write_key(encoder, 5);
            encoder.write_byte_string(&self.proof);
        }
    }
}

impl fmt::Debug for ProtectedFirstActivationPreparedV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProtectedFirstActivationPreparedV1")
            .field("protocol_schema_version", &self.protocol_schema_version)
            .field("pending", &self.pending)
            .field("protected_fields", &"<redacted>")
            .finish()
    }
}

impl DeterministicCodec for ProtectedFirstActivationPreparedV1 {
    const MESSAGE_TYPE_ID: u32 = 7;

    fn encode(&self, encoder: &mut CborEncoder) -> Result<(), EncodeError> {
        self.encode_fields(encoder, true);
        Ok(())
    }

    fn decode(type_id: u32, decoder: &mut CborDecoder<'_>) -> Result<Self, DecodeError> {
        if type_id != Self::MESSAGE_TYPE_ID || decoder.read_map_header(6)? != 6 {
            return Err(DecodeError::UnknownMessageType { type_id });
        }
        expect_key(decoder, 0)?;
        expect_message_type(decoder, Self::MESSAGE_TYPE_ID)?;
        expect_key(decoder, 1)?;
        if decoder.read_unsigned(u64::from(u32::MAX))? != u64::from(PROTOCOL_SCHEMA_VERSION) {
            return Err(DecodeError::UnknownField { key: 1 });
        }
        expect_key(decoder, 2)?;
        let launch_authority_id = decode_fixed::<16>(decoder)?;
        expect_key(decoder, 3)?;
        let desktop_host_instance_id = decode_fixed::<16>(decoder)?;
        expect_key(decoder, 4)?;
        let pending = decode_pending(decoder)?;
        expect_key(decoder, 5)?;
        let proof = decode_fixed::<32>(decoder)?;
        Ok(Self {
            protocol_schema_version: PROTOCOL_SCHEMA_VERSION,
            launch_authority_id,
            desktop_host_instance_id,
            pending,
            proof,
        })
    }
}

/// Desktop commit for the exact durably persisted first-activation record.
#[derive(Clone, Eq, PartialEq)]
pub struct ProtectedFirstActivationCommitV1 {
    protocol_schema_version: u32,
    launch_authority_id: [u8; 16],
    desktop_host_instance_id: [u8; 16],
    pending: PendingFirstActivationV1,
    proof: [u8; 32],
}

impl ProtectedFirstActivationCommitV1 {
    /// Builds an unsigned exact commit.
    #[must_use]
    pub const fn new(
        launch_authority_id: [u8; 16],
        desktop_host_instance_id: [u8; 16],
        pending: PendingFirstActivationV1,
    ) -> Self {
        Self {
            protocol_schema_version: PROTOCOL_SCHEMA_VERSION,
            launch_authority_id,
            desktop_host_instance_id,
            pending,
            proof: [0; 32],
        }
    }

    /// Signs the exact canonical commit transcript.
    pub fn sign(&mut self, keys: &ProtectedActivationKeys) {
        self.proof = authenticated_mac(
            keys.readiness_key(),
            FIRST_ACTIVATION_COMMIT_DOMAIN,
            &self.unsigned_payload(),
        );
    }

    /// Verifies exact launch, preparation, and HMAC binding.
    pub fn verify_exact(
        &self,
        request: &ProtectedLaunchRequestV1,
        expected_pending: &PendingFirstActivationV1,
        keys: &ProtectedActivationKeys,
    ) -> Result<(), LaunchAuthorityError> {
        if self.launch_authority_id != request.launch_authority_id
            || self.desktop_host_instance_id != request.desktop_host_instance_id
        {
            return Err(LaunchAuthorityError::MissingLaunchAuthority);
        }
        if &self.pending != expected_pending {
            return Err(LaunchAuthorityError::FirstActivationPreparationMismatch);
        }
        let expected = authenticated_mac(
            keys.readiness_key(),
            FIRST_ACTIVATION_COMMIT_DOMAIN,
            &self.unsigned_payload(),
        );
        if !bool::from(expected.ct_eq(&self.proof)) {
            return Err(LaunchAuthorityError::ReadinessProofMismatch);
        }
        Ok(())
    }

    /// Encodes the deterministic bounded commit frame.
    pub fn encode_frame(&self) -> Result<Vec<u8>, EncodeError> {
        encode_codec_frame(
            self,
            &FrameLimits {
                max_frame_bytes: MAX_FRAME_BYTES,
            },
        )
    }

    /// Decodes one deterministic bounded commit frame.
    pub fn decode_frame(frame: &[u8]) -> Result<Self, DecodeError> {
        decode_codec_frame(frame, &decode_limits())
    }

    fn unsigned_payload(&self) -> Vec<u8> {
        let mut encoder = CborEncoder::new();
        self.encode_fields(&mut encoder, false);
        encoder.into_bytes()
    }

    fn encode_fields(&self, encoder: &mut CborEncoder, include_proof: bool) {
        encoder.write_map_header(if include_proof { 6 } else { 5 });
        write_key(encoder, 0);
        encoder.write_unsigned(u64::from(Self::MESSAGE_TYPE_ID));
        write_key(encoder, 1);
        encoder.write_unsigned(u64::from(self.protocol_schema_version));
        write_key(encoder, 2);
        encoder.write_byte_string(&self.launch_authority_id);
        write_key(encoder, 3);
        encoder.write_byte_string(&self.desktop_host_instance_id);
        write_key(encoder, 4);
        encode_pending(encoder, &self.pending);
        if include_proof {
            write_key(encoder, 5);
            encoder.write_byte_string(&self.proof);
        }
    }
}

impl fmt::Debug for ProtectedFirstActivationCommitV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProtectedFirstActivationCommitV1")
            .field("protocol_schema_version", &self.protocol_schema_version)
            .field("pending", &self.pending)
            .field("protected_fields", &"<redacted>")
            .finish()
    }
}

impl DeterministicCodec for ProtectedFirstActivationCommitV1 {
    const MESSAGE_TYPE_ID: u32 = 8;

    fn encode(&self, encoder: &mut CborEncoder) -> Result<(), EncodeError> {
        self.encode_fields(encoder, true);
        Ok(())
    }

    fn decode(type_id: u32, decoder: &mut CborDecoder<'_>) -> Result<Self, DecodeError> {
        if type_id != Self::MESSAGE_TYPE_ID || decoder.read_map_header(6)? != 6 {
            return Err(DecodeError::UnknownMessageType { type_id });
        }
        expect_key(decoder, 0)?;
        expect_message_type(decoder, Self::MESSAGE_TYPE_ID)?;
        expect_key(decoder, 1)?;
        if decoder.read_unsigned(u64::from(u32::MAX))? != u64::from(PROTOCOL_SCHEMA_VERSION) {
            return Err(DecodeError::UnknownField { key: 1 });
        }
        expect_key(decoder, 2)?;
        let launch_authority_id = decode_fixed::<16>(decoder)?;
        expect_key(decoder, 3)?;
        let desktop_host_instance_id = decode_fixed::<16>(decoder)?;
        expect_key(decoder, 4)?;
        let pending = decode_pending(decoder)?;
        expect_key(decoder, 5)?;
        let proof = decode_fixed::<32>(decoder)?;
        Ok(Self {
            protocol_schema_version: PROTOCOL_SCHEMA_VERSION,
            launch_authority_id,
            desktop_host_instance_id,
            pending,
            proof,
        })
    }
}

/// Exact launch tuple required for renewal and shutdown ownership proofs.
#[derive(Clone, Eq, PartialEq)]
pub struct ProtectedOwnedLaunchV1 {
    launch_authority_id: [u8; 16],
    desktop_host_instance_id: [u8; 16],
    executable: ExecutableIdentityV1,
    profile: ProtectedRuntimeProfileV1,
    stable: StableRuntimeBindingV1,
    daemon_instance_id: [u8; 16],
    launch_generation: u64,
    session_id: [u8; 16],
}

impl ProtectedOwnedLaunchV1 {
    #[allow(clippy::too_many_arguments)]
    fn new(
        launch_authority_id: [u8; 16],
        desktop_host_instance_id: [u8; 16],
        executable: ExecutableIdentityV1,
        profile: ProtectedRuntimeProfileV1,
        stable: StableRuntimeBindingV1,
        daemon_instance_id: [u8; 16],
        launch_generation: u64,
        session_id: [u8; 16],
    ) -> Result<Self, LaunchAuthorityError> {
        if validate_uuid_v7_bytes(&launch_authority_id).is_err()
            || validate_uuid_v7_bytes(&desktop_host_instance_id).is_err()
            || validate_uuid_v7_bytes(&daemon_instance_id).is_err()
            || validate_uuid_v7_bytes(&session_id).is_err()
            || daemon_instance_id == session_id
            || launch_generation == 0
        {
            return Err(LaunchAuthorityError::InstanceGenerationSessionMismatch);
        }
        Ok(Self {
            launch_authority_id,
            desktop_host_instance_id,
            executable,
            profile,
            stable,
            daemon_instance_id,
            launch_generation,
            session_id,
        })
    }

    pub const fn launch_authority_id(&self) -> &[u8; 16] {
        &self.launch_authority_id
    }

    pub const fn desktop_host_instance_id(&self) -> &[u8; 16] {
        &self.desktop_host_instance_id
    }

    pub const fn executable(&self) -> &ExecutableIdentityV1 {
        &self.executable
    }

    pub const fn profile(&self) -> &ProtectedRuntimeProfileV1 {
        &self.profile
    }

    pub const fn stable(&self) -> &StableRuntimeBindingV1 {
        &self.stable
    }

    pub const fn daemon_instance_id(&self) -> &[u8; 16] {
        &self.daemon_instance_id
    }

    pub const fn launch_generation(&self) -> u64 {
        self.launch_generation
    }

    pub const fn session_id(&self) -> &[u8; 16] {
        &self.session_id
    }
}

impl fmt::Debug for ProtectedOwnedLaunchV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProtectedOwnedLaunchV1")
            .field("launch_generation", &self.launch_generation)
            .field("protected_fields", &"<redacted>")
            .finish()
    }
}

/// Monotonic protected request for one replacement HTTP session authority.
#[derive(Clone, Eq, PartialEq)]
pub struct ProtectedRenewRequestV1 {
    protocol_schema_version: u32,
    owned_launch: ProtectedOwnedLaunchV1,
    sequence: u64,
    nonce: [u8; 32],
    proof: [u8; 32],
}

impl ProtectedRenewRequestV1 {
    /// Builds an unsigned renewal request.
    pub fn new(
        owned_launch: ProtectedOwnedLaunchV1,
        sequence: u64,
        nonce: [u8; 32],
    ) -> Result<Self, LaunchAuthorityError> {
        if sequence == 0 || nonce == [0; 32] {
            return Err(LaunchAuthorityError::RenewalReplay);
        }
        Ok(Self {
            protocol_schema_version: PROTOCOL_SCHEMA_VERSION,
            owned_launch,
            sequence,
            nonce,
            proof: [0; 32],
        })
    }

    /// Signs the exact canonical renewal transcript.
    pub fn sign(&mut self, keys: &ProtectedActivationKeys) {
        self.proof = authenticated_mac(
            keys.renewal_key_ref(),
            RENEW_DOMAIN,
            &self.unsigned_payload(),
        );
    }

    /// Verifies exact ownership, strictly next sequence, and proof.
    pub fn verify_exact(
        &self,
        expected: &ProtectedOwnedLaunchV1,
        last_sequence: u64,
        keys: &ProtectedActivationKeys,
    ) -> Result<(), LaunchAuthorityError> {
        if &self.owned_launch != expected {
            return Err(LaunchAuthorityError::OwnershipMismatch);
        }
        let next_sequence = last_sequence
            .checked_add(1)
            .ok_or(LaunchAuthorityError::RenewalReplay)?;
        if self.sequence != next_sequence || self.nonce == [0; 32] {
            return Err(LaunchAuthorityError::RenewalReplay);
        }
        let expected_proof = authenticated_mac(
            keys.renewal_key_ref(),
            RENEW_DOMAIN,
            &self.unsigned_payload(),
        );
        if !bool::from(expected_proof.ct_eq(&self.proof)) {
            return Err(LaunchAuthorityError::ReadinessProofMismatch);
        }
        Ok(())
    }

    pub const fn owned_launch(&self) -> &ProtectedOwnedLaunchV1 {
        &self.owned_launch
    }

    pub const fn sequence(&self) -> u64 {
        self.sequence
    }

    pub const fn nonce(&self) -> &[u8; 32] {
        &self.nonce
    }

    pub fn encode_frame(&self) -> Result<Vec<u8>, EncodeError> {
        encode_codec_frame(
            self,
            &FrameLimits {
                max_frame_bytes: MAX_FRAME_BYTES,
            },
        )
    }

    pub fn decode_frame(frame: &[u8]) -> Result<Self, DecodeError> {
        decode_codec_frame(frame, &decode_limits())
    }

    fn unsigned_payload(&self) -> Vec<u8> {
        let mut encoder = CborEncoder::new();
        self.encode_fields(&mut encoder, false);
        encoder.into_bytes()
    }

    fn encode_fields(&self, encoder: &mut CborEncoder, include_proof: bool) {
        encoder.write_map_header(if include_proof { 6 } else { 5 });
        write_key(encoder, 0);
        encoder.write_unsigned(u64::from(Self::MESSAGE_TYPE_ID));
        write_key(encoder, 1);
        encoder.write_unsigned(u64::from(self.protocol_schema_version));
        write_key(encoder, 2);
        encode_owned_launch(encoder, &self.owned_launch);
        write_key(encoder, 3);
        encoder.write_unsigned(self.sequence);
        write_key(encoder, 4);
        encoder.write_byte_string(&self.nonce);
        if include_proof {
            write_key(encoder, 5);
            encoder.write_byte_string(&self.proof);
        }
    }
}

impl fmt::Debug for ProtectedRenewRequestV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProtectedRenewRequestV1")
            .field("sequence", &self.sequence)
            .field("protected_fields", &"<redacted>")
            .finish()
    }
}

impl DeterministicCodec for ProtectedRenewRequestV1 {
    const MESSAGE_TYPE_ID: u32 = 3;

    fn encode(&self, encoder: &mut CborEncoder) -> Result<(), EncodeError> {
        self.encode_fields(encoder, true);
        Ok(())
    }

    fn decode(type_id: u32, decoder: &mut CborDecoder<'_>) -> Result<Self, DecodeError> {
        if type_id != Self::MESSAGE_TYPE_ID || decoder.read_map_header(6)? != 6 {
            return Err(DecodeError::UnknownMessageType { type_id });
        }
        expect_key(decoder, 0)?;
        expect_message_type(decoder, Self::MESSAGE_TYPE_ID)?;
        expect_schema(decoder)?;
        expect_key(decoder, 2)?;
        let owned_launch = decode_owned_launch(decoder)?;
        expect_key(decoder, 3)?;
        let sequence = decoder.read_unsigned(u64::MAX)?;
        expect_key(decoder, 4)?;
        let nonce = decode_fixed::<32>(decoder)?;
        expect_key(decoder, 5)?;
        let proof = decode_fixed::<32>(decoder)?;
        let mut value = Self::new(owned_launch, sequence, nonce)
            .map_err(|_| DecodeError::UnknownField { key: 4 })?;
        value.proof = proof;
        Ok(value)
    }
}

/// One-time protected bootstrap ticket for a rotated HTTP session.
#[derive(Clone, Eq, PartialEq)]
pub struct ProtectedRenewTicketV1 {
    protocol_schema_version: u32,
    owned_launch: ProtectedOwnedLaunchV1,
    sequence: u64,
    nonce: [u8; 32],
    next_session_id: [u8; 16],
    bootstrap_ticket: [u8; 32],
    issued_at_monotonic_millis: u64,
    expires_at_monotonic_millis: u64,
    proof: [u8; 32],
}

impl ProtectedRenewTicketV1 {
    /// Builds an unsigned ticket for the exact accepted renewal.
    pub fn new(
        request: &ProtectedRenewRequestV1,
        next_session_id: [u8; 16],
        bootstrap_ticket: [u8; 32],
        issued_at_monotonic_millis: u64,
        expires_at_monotonic_millis: u64,
    ) -> Result<Self, LaunchAuthorityError> {
        if validate_uuid_v7_bytes(&next_session_id).is_err()
            || next_session_id == *request.owned_launch.session_id()
            || next_session_id == *request.owned_launch.daemon_instance_id()
            || bootstrap_ticket == [0; 32]
            || expires_at_monotonic_millis <= issued_at_monotonic_millis
            || expires_at_monotonic_millis.saturating_sub(issued_at_monotonic_millis)
                > MAX_LAUNCH_TTL_MILLIS
        {
            return Err(LaunchAuthorityError::RenewalUnavailable);
        }
        Ok(Self {
            protocol_schema_version: PROTOCOL_SCHEMA_VERSION,
            owned_launch: request.owned_launch.clone(),
            sequence: request.sequence,
            nonce: request.nonce,
            next_session_id,
            bootstrap_ticket,
            issued_at_monotonic_millis,
            expires_at_monotonic_millis,
            proof: [0; 32],
        })
    }

    /// Signs the exact canonical ticket transcript.
    pub fn sign(&mut self, keys: &ProtectedActivationKeys) {
        self.proof = authenticated_mac(
            keys.renewal_key_ref(),
            RENEW_DOMAIN,
            &self.unsigned_payload(),
        );
    }

    /// Verifies the ticket against the exact accepted renewal.
    pub fn verify_exact(
        &self,
        request: &ProtectedRenewRequestV1,
        keys: &ProtectedActivationKeys,
    ) -> Result<(), LaunchAuthorityError> {
        if self.owned_launch != request.owned_launch
            || self.sequence != request.sequence
            || self.nonce != request.nonce
        {
            return Err(LaunchAuthorityError::RenewalReplay);
        }
        if validate_uuid_v7_bytes(&self.next_session_id).is_err()
            || self.next_session_id == *self.owned_launch.session_id()
            || self.next_session_id == *self.owned_launch.daemon_instance_id()
            || self.bootstrap_ticket == [0; 32]
            || self.expires_at_monotonic_millis <= self.issued_at_monotonic_millis
            || self
                .expires_at_monotonic_millis
                .saturating_sub(self.issued_at_monotonic_millis)
                > MAX_LAUNCH_TTL_MILLIS
        {
            return Err(LaunchAuthorityError::RenewalUnavailable);
        }
        let expected = authenticated_mac(
            keys.renewal_key_ref(),
            RENEW_DOMAIN,
            &self.unsigned_payload(),
        );
        if !bool::from(expected.ct_eq(&self.proof)) {
            return Err(LaunchAuthorityError::ReadinessProofMismatch);
        }
        Ok(())
    }

    pub const fn next_session_id(&self) -> &[u8; 16] {
        &self.next_session_id
    }

    /// Copies the one-time bootstrap ticket into a zeroizing owner.
    #[must_use]
    pub fn bootstrap_ticket(&self) -> Zeroizing<[u8; 32]> {
        Zeroizing::new(self.bootstrap_ticket)
    }

    pub const fn issued_at_monotonic_millis(&self) -> u64 {
        self.issued_at_monotonic_millis
    }

    pub const fn expires_at_monotonic_millis(&self) -> u64 {
        self.expires_at_monotonic_millis
    }

    /// Returns the ownership tuple after the ticket's session rotation.
    #[must_use]
    pub fn next_owned_launch(&self) -> ProtectedOwnedLaunchV1 {
        ProtectedOwnedLaunchV1::new(
            self.owned_launch.launch_authority_id,
            self.owned_launch.desktop_host_instance_id,
            self.owned_launch.executable.clone(),
            self.owned_launch.profile.clone(),
            self.owned_launch.stable.clone(),
            self.owned_launch.daemon_instance_id,
            self.owned_launch.launch_generation,
            self.next_session_id,
        )
        .expect("validated renewal ticket has a valid next session")
    }

    pub fn encode_frame(&self) -> Result<Vec<u8>, EncodeError> {
        encode_codec_frame(
            self,
            &FrameLimits {
                max_frame_bytes: MAX_FRAME_BYTES,
            },
        )
    }

    pub fn decode_frame(frame: &[u8]) -> Result<Self, DecodeError> {
        decode_codec_frame(frame, &decode_limits())
    }

    fn unsigned_payload(&self) -> Vec<u8> {
        let mut encoder = CborEncoder::new();
        self.encode_fields(&mut encoder, false);
        encoder.into_bytes()
    }

    fn encode_fields(&self, encoder: &mut CborEncoder, include_proof: bool) {
        encoder.write_map_header(if include_proof { 10 } else { 9 });
        write_key(encoder, 0);
        encoder.write_unsigned(u64::from(Self::MESSAGE_TYPE_ID));
        write_key(encoder, 1);
        encoder.write_unsigned(u64::from(self.protocol_schema_version));
        write_key(encoder, 2);
        encode_owned_launch(encoder, &self.owned_launch);
        write_key(encoder, 3);
        encoder.write_unsigned(self.sequence);
        write_key(encoder, 4);
        encoder.write_byte_string(&self.nonce);
        write_key(encoder, 5);
        encoder.write_byte_string(&self.next_session_id);
        write_key(encoder, 6);
        encoder.write_byte_string(&self.bootstrap_ticket);
        write_key(encoder, 7);
        encoder.write_unsigned(self.issued_at_monotonic_millis);
        write_key(encoder, 8);
        encoder.write_unsigned(self.expires_at_monotonic_millis);
        if include_proof {
            write_key(encoder, 9);
            encoder.write_byte_string(&self.proof);
        }
    }
}

impl fmt::Debug for ProtectedRenewTicketV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProtectedRenewTicketV1")
            .field("sequence", &self.sequence)
            .field(
                "expires_at_monotonic_millis",
                &self.expires_at_monotonic_millis,
            )
            .field("protected_fields", &"<redacted>")
            .finish()
    }
}

impl Drop for ProtectedRenewTicketV1 {
    fn drop(&mut self) {
        self.bootstrap_ticket.zeroize();
    }
}

impl DeterministicCodec for ProtectedRenewTicketV1 {
    const MESSAGE_TYPE_ID: u32 = 4;

    fn encode(&self, encoder: &mut CborEncoder) -> Result<(), EncodeError> {
        self.encode_fields(encoder, true);
        Ok(())
    }

    fn decode(type_id: u32, decoder: &mut CborDecoder<'_>) -> Result<Self, DecodeError> {
        if type_id != Self::MESSAGE_TYPE_ID || decoder.read_map_header(10)? != 10 {
            return Err(DecodeError::UnknownMessageType { type_id });
        }
        expect_key(decoder, 0)?;
        expect_message_type(decoder, Self::MESSAGE_TYPE_ID)?;
        expect_schema(decoder)?;
        expect_key(decoder, 2)?;
        let owned_launch = decode_owned_launch(decoder)?;
        expect_key(decoder, 3)?;
        let sequence = decoder.read_unsigned(u64::MAX)?;
        expect_key(decoder, 4)?;
        let nonce = decode_fixed::<32>(decoder)?;
        expect_key(decoder, 5)?;
        let next_session_id = decode_fixed::<16>(decoder)?;
        expect_key(decoder, 6)?;
        let bootstrap_ticket = decode_fixed::<32>(decoder)?;
        expect_key(decoder, 7)?;
        let issued_at_monotonic_millis = decoder.read_unsigned(u64::MAX)?;
        expect_key(decoder, 8)?;
        let expires_at_monotonic_millis = decoder.read_unsigned(u64::MAX)?;
        expect_key(decoder, 9)?;
        let proof = decode_fixed::<32>(decoder)?;
        let request = ProtectedRenewRequestV1 {
            protocol_schema_version: PROTOCOL_SCHEMA_VERSION,
            owned_launch,
            sequence,
            nonce,
            proof: [1; 32],
        };
        let mut value = Self::new(
            &request,
            next_session_id,
            bootstrap_ticket,
            issued_at_monotonic_millis,
            expires_at_monotonic_millis,
        )
        .map_err(|_| DecodeError::UnknownField { key: 7 })?;
        value.proof = proof;
        Ok(value)
    }
}

/// HMAC-authenticated orderly shutdown request for an exact owned launch.
#[derive(Clone, Eq, PartialEq)]
pub struct ProtectedShutdownV1 {
    protocol_schema_version: u32,
    owned_launch: ProtectedOwnedLaunchV1,
    proof: [u8; 32],
}

impl ProtectedShutdownV1 {
    #[must_use]
    pub const fn new(owned_launch: ProtectedOwnedLaunchV1) -> Self {
        Self {
            protocol_schema_version: PROTOCOL_SCHEMA_VERSION,
            owned_launch,
            proof: [0; 32],
        }
    }

    pub fn sign(&mut self, keys: &ProtectedActivationKeys) {
        self.proof = authenticated_mac(
            keys.shutdown_key_ref(),
            SHUTDOWN_DOMAIN,
            &self.unsigned_payload(),
        );
    }

    pub fn verify_exact(
        &self,
        expected: &ProtectedOwnedLaunchV1,
        keys: &ProtectedActivationKeys,
    ) -> Result<(), LaunchAuthorityError> {
        if &self.owned_launch != expected {
            return Err(LaunchAuthorityError::OwnershipMismatch);
        }
        let proof = authenticated_mac(
            keys.shutdown_key_ref(),
            SHUTDOWN_DOMAIN,
            &self.unsigned_payload(),
        );
        if !bool::from(proof.ct_eq(&self.proof)) {
            return Err(LaunchAuthorityError::ReadinessProofMismatch);
        }
        Ok(())
    }

    pub const fn owned_launch(&self) -> &ProtectedOwnedLaunchV1 {
        &self.owned_launch
    }

    pub fn encode_frame(&self) -> Result<Vec<u8>, EncodeError> {
        encode_codec_frame(
            self,
            &FrameLimits {
                max_frame_bytes: MAX_FRAME_BYTES,
            },
        )
    }

    pub fn decode_frame(frame: &[u8]) -> Result<Self, DecodeError> {
        decode_codec_frame(frame, &decode_limits())
    }

    fn unsigned_payload(&self) -> Vec<u8> {
        let mut encoder = CborEncoder::new();
        self.encode_fields(&mut encoder, false);
        encoder.into_bytes()
    }

    fn encode_fields(&self, encoder: &mut CborEncoder, include_proof: bool) {
        encoder.write_map_header(if include_proof { 4 } else { 3 });
        write_key(encoder, 0);
        encoder.write_unsigned(u64::from(Self::MESSAGE_TYPE_ID));
        write_key(encoder, 1);
        encoder.write_unsigned(u64::from(self.protocol_schema_version));
        write_key(encoder, 2);
        encode_owned_launch(encoder, &self.owned_launch);
        if include_proof {
            write_key(encoder, 3);
            encoder.write_byte_string(&self.proof);
        }
    }
}

impl fmt::Debug for ProtectedShutdownV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProtectedShutdownV1")
            .field("protected_fields", &"<redacted>")
            .finish()
    }
}

impl DeterministicCodec for ProtectedShutdownV1 {
    const MESSAGE_TYPE_ID: u32 = 5;

    fn encode(&self, encoder: &mut CborEncoder) -> Result<(), EncodeError> {
        self.encode_fields(encoder, true);
        Ok(())
    }

    fn decode(type_id: u32, decoder: &mut CborDecoder<'_>) -> Result<Self, DecodeError> {
        if type_id != Self::MESSAGE_TYPE_ID || decoder.read_map_header(4)? != 4 {
            return Err(DecodeError::UnknownMessageType { type_id });
        }
        expect_key(decoder, 0)?;
        expect_message_type(decoder, Self::MESSAGE_TYPE_ID)?;
        expect_schema(decoder)?;
        expect_key(decoder, 2)?;
        let owned_launch = decode_owned_launch(decoder)?;
        expect_key(decoder, 3)?;
        let proof = decode_fixed::<32>(decoder)?;
        Ok(Self {
            protocol_schema_version: PROTOCOL_SCHEMA_VERSION,
            owned_launch,
            proof,
        })
    }
}

/// Protected acknowledgement that the exact owned launch accepted shutdown.
#[derive(Clone, Eq, PartialEq)]
pub struct ProtectedShutdownAckV1 {
    protocol_schema_version: u32,
    owned_launch: ProtectedOwnedLaunchV1,
    graceful: bool,
    proof: [u8; 32],
}

impl ProtectedShutdownAckV1 {
    #[must_use]
    pub const fn new(owned_launch: ProtectedOwnedLaunchV1, graceful: bool) -> Self {
        Self {
            protocol_schema_version: PROTOCOL_SCHEMA_VERSION,
            owned_launch,
            graceful,
            proof: [0; 32],
        }
    }

    pub fn sign(&mut self, keys: &ProtectedActivationKeys) {
        self.proof = authenticated_mac(
            keys.shutdown_key_ref(),
            SHUTDOWN_DOMAIN,
            &self.unsigned_payload(),
        );
    }

    pub fn verify_exact(
        &self,
        expected: &ProtectedOwnedLaunchV1,
        keys: &ProtectedActivationKeys,
    ) -> Result<(), LaunchAuthorityError> {
        if &self.owned_launch != expected {
            return Err(LaunchAuthorityError::OwnershipMismatch);
        }
        let proof = authenticated_mac(
            keys.shutdown_key_ref(),
            SHUTDOWN_DOMAIN,
            &self.unsigned_payload(),
        );
        if !bool::from(proof.ct_eq(&self.proof)) {
            return Err(LaunchAuthorityError::ReadinessProofMismatch);
        }
        Ok(())
    }

    pub const fn graceful(&self) -> bool {
        self.graceful
    }

    pub fn encode_frame(&self) -> Result<Vec<u8>, EncodeError> {
        encode_codec_frame(
            self,
            &FrameLimits {
                max_frame_bytes: MAX_FRAME_BYTES,
            },
        )
    }

    pub fn decode_frame(frame: &[u8]) -> Result<Self, DecodeError> {
        decode_codec_frame(frame, &decode_limits())
    }

    fn unsigned_payload(&self) -> Vec<u8> {
        let mut encoder = CborEncoder::new();
        self.encode_fields(&mut encoder, false);
        encoder.into_bytes()
    }

    fn encode_fields(&self, encoder: &mut CborEncoder, include_proof: bool) {
        encoder.write_map_header(if include_proof { 5 } else { 4 });
        write_key(encoder, 0);
        encoder.write_unsigned(u64::from(Self::MESSAGE_TYPE_ID));
        write_key(encoder, 1);
        encoder.write_unsigned(u64::from(self.protocol_schema_version));
        write_key(encoder, 2);
        encode_owned_launch(encoder, &self.owned_launch);
        write_key(encoder, 3);
        encoder.write_bool(self.graceful);
        if include_proof {
            write_key(encoder, 4);
            encoder.write_byte_string(&self.proof);
        }
    }
}

impl fmt::Debug for ProtectedShutdownAckV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProtectedShutdownAckV1")
            .field("graceful", &self.graceful)
            .field("protected_fields", &"<redacted>")
            .finish()
    }
}

impl DeterministicCodec for ProtectedShutdownAckV1 {
    const MESSAGE_TYPE_ID: u32 = 6;

    fn encode(&self, encoder: &mut CborEncoder) -> Result<(), EncodeError> {
        self.encode_fields(encoder, true);
        Ok(())
    }

    fn decode(type_id: u32, decoder: &mut CborDecoder<'_>) -> Result<Self, DecodeError> {
        if type_id != Self::MESSAGE_TYPE_ID || decoder.read_map_header(5)? != 5 {
            return Err(DecodeError::UnknownMessageType { type_id });
        }
        expect_key(decoder, 0)?;
        expect_message_type(decoder, Self::MESSAGE_TYPE_ID)?;
        expect_schema(decoder)?;
        expect_key(decoder, 2)?;
        let owned_launch = decode_owned_launch(decoder)?;
        expect_key(decoder, 3)?;
        let graceful = decoder.read_bool()?;
        expect_key(decoder, 4)?;
        let proof = decode_fixed::<32>(decoder)?;
        Ok(Self {
            protocol_schema_version: PROTOCOL_SCHEMA_VERSION,
            owned_launch,
            graceful,
            proof,
        })
    }
}

/// Authenticated readiness for exactly one protected launch.
#[derive(Clone, Eq, PartialEq)]
pub struct ProtectedReadyV1 {
    protocol_schema_version: u32,
    launch_authority_id: [u8; 16],
    desktop_host_instance_id: [u8; 16],
    executable: ExecutableIdentityV1,
    profile: ProtectedRuntimeProfileV1,
    stable: StableRuntimeBindingV1,
    daemon_instance_id: [u8; 16],
    launch_generation: u64,
    session_id: [u8; 16],
    endpoint: String,
    certificate_sha256: [u8; 32],
    certificate_der: Vec<u8>,
    capabilities: Vec<String>,
    readiness_proof: [u8; 32],
}

impl ProtectedReadyV1 {
    /// Builds an unsigned exact readiness value.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        launch_authority_id: [u8; 16],
        desktop_host_instance_id: [u8; 16],
        executable: ExecutableIdentityV1,
        profile: ProtectedRuntimeProfileV1,
        stable: StableRuntimeBindingV1,
        daemon_instance_id: [u8; 16],
        launch_generation: u64,
        session_id: [u8; 16],
        endpoint: impl Into<String>,
        certificate_sha256: [u8; 32],
        certificate_der: Vec<u8>,
        capabilities: Vec<String>,
    ) -> Result<Self, LaunchAuthorityError> {
        let endpoint = endpoint.into();
        if validate_uuid_v7_bytes(&launch_authority_id).is_err()
            || validate_uuid_v7_bytes(&desktop_host_instance_id).is_err()
            || validate_uuid_v7_bytes(&daemon_instance_id).is_err()
            || validate_uuid_v7_bytes(&session_id).is_err()
            || daemon_instance_id == session_id
            || launch_generation == 0
            || !valid_text(&endpoint, MAX_TEXT_BYTES)
            || certificate_sha256 == [0; 32]
            || certificate_der.is_empty()
            || certificate_der.len() > MAX_CERTIFICATE_DER_BYTES
            || capabilities.is_empty()
            || capabilities.len() > MAX_CAPABILITIES
            || capabilities
                .iter()
                .any(|capability| !valid_text(capability, MAX_PROFILE_ID_BYTES))
        {
            return Err(LaunchAuthorityError::InstanceGenerationSessionMismatch);
        }
        Ok(Self {
            protocol_schema_version: PROTOCOL_SCHEMA_VERSION,
            launch_authority_id,
            desktop_host_instance_id,
            executable,
            profile,
            stable,
            daemon_instance_id,
            launch_generation,
            session_id,
            endpoint,
            certificate_sha256,
            certificate_der,
            capabilities,
            readiness_proof: [0; 32],
        })
    }

    /// Signs the exact canonical readiness transcript.
    pub fn sign(&mut self, keys: &ProtectedActivationKeys) {
        self.readiness_proof = authenticated_mac(
            keys.readiness_key(),
            READINESS_DOMAIN,
            &self.unsigned_payload(),
        );
    }

    /// Verifies proof plus every launch-pinned stable field.
    pub fn verify_exact(
        &self,
        request: &ProtectedLaunchRequestV1,
        keys: &ProtectedActivationKeys,
    ) -> Result<(), LaunchAuthorityError> {
        if self.launch_authority_id != request.launch_authority_id
            || self.desktop_host_instance_id != request.desktop_host_instance_id
        {
            return Err(LaunchAuthorityError::MissingLaunchAuthority);
        }
        if self.executable != request.executable {
            return Err(LaunchAuthorityError::ExecutableIdentityMismatch);
        }
        if self.profile != request.profile {
            return Err(
                if self.profile.transport_profile_id == EXTERNAL_TRANSPORT_PROFILE_ID {
                    LaunchAuthorityError::DowngradedExternalProfile
                } else {
                    LaunchAuthorityError::ProfileHashMismatch
                },
            );
        }
        if let Some(expected) = request.activation_disposition.expected_stable()
            && self.stable != *expected
        {
            return Err(LaunchAuthorityError::ProfileHashMismatch);
        }
        if self.launch_generation == 0
            || self.daemon_instance_id == self.session_id
            || validate_uuid_v7_bytes(&self.daemon_instance_id).is_err()
            || validate_uuid_v7_bytes(&self.session_id).is_err()
        {
            return Err(LaunchAuthorityError::InstanceGenerationSessionMismatch);
        }
        let expected = authenticated_mac(
            keys.readiness_key(),
            READINESS_DOMAIN,
            &self.unsigned_payload(),
        );
        if !bool::from(expected.ct_eq(&self.readiness_proof)) {
            return Err(LaunchAuthorityError::ReadinessProofMismatch);
        }
        Ok(())
    }

    /// Encodes the signed deterministic bounded readiness frame.
    pub fn encode_frame(&self) -> Result<Vec<u8>, EncodeError> {
        encode_codec_frame(
            self,
            &FrameLimits {
                max_frame_bytes: MAX_FRAME_BYTES,
            },
        )
    }

    /// Decodes one exact deterministic bounded readiness frame.
    pub fn decode_frame(frame: &[u8]) -> Result<Self, DecodeError> {
        decode_codec_frame(frame, &decode_limits())
    }

    pub const fn stable(&self) -> &StableRuntimeBindingV1 {
        &self.stable
    }

    pub const fn profile(&self) -> &ProtectedRuntimeProfileV1 {
        &self.profile
    }

    pub const fn executable(&self) -> &ExecutableIdentityV1 {
        &self.executable
    }

    pub const fn daemon_instance_id(&self) -> &[u8; 16] {
        &self.daemon_instance_id
    }

    pub const fn launch_generation(&self) -> u64 {
        self.launch_generation
    }

    pub const fn session_id(&self) -> &[u8; 16] {
        &self.session_id
    }

    pub fn endpoint(&self) -> &str {
        &self.endpoint
    }

    pub const fn certificate_sha256(&self) -> &[u8; 32] {
        &self.certificate_sha256
    }

    pub fn certificate_der(&self) -> &[u8] {
        &self.certificate_der
    }

    pub fn capabilities(&self) -> &[String] {
        &self.capabilities
    }

    /// Returns the exact non-secret ownership tuple for control messages.
    #[must_use]
    pub fn owned_launch(&self) -> ProtectedOwnedLaunchV1 {
        ProtectedOwnedLaunchV1::new(
            self.launch_authority_id,
            self.desktop_host_instance_id,
            self.executable.clone(),
            self.profile.clone(),
            self.stable.clone(),
            self.daemon_instance_id,
            self.launch_generation,
            self.session_id,
        )
        .expect("validated readiness always has a valid owned-launch tuple")
    }

    fn unsigned_payload(&self) -> Vec<u8> {
        let mut encoder = CborEncoder::new();
        self.encode_fields(&mut encoder, false)
            .expect("in-memory validated readiness is encodable");
        encoder.into_bytes()
    }

    fn encode_fields(
        &self,
        encoder: &mut CborEncoder,
        include_proof: bool,
    ) -> Result<(), EncodeError> {
        encoder.write_map_header(if include_proof { 15 } else { 14 });
        write_key(encoder, 0);
        encoder.write_unsigned(u64::from(Self::MESSAGE_TYPE_ID));
        write_key(encoder, 1);
        encoder.write_unsigned(u64::from(self.protocol_schema_version));
        write_key(encoder, 2);
        encoder.write_byte_string(&self.launch_authority_id);
        write_key(encoder, 3);
        encoder.write_byte_string(&self.desktop_host_instance_id);
        write_key(encoder, 4);
        encode_executable(encoder, &self.executable);
        write_key(encoder, 5);
        encode_profile(encoder, &self.profile);
        write_key(encoder, 6);
        encode_stable(encoder, &self.stable);
        write_key(encoder, 7);
        encoder.write_byte_string(&self.daemon_instance_id);
        write_key(encoder, 8);
        encoder.write_unsigned(self.launch_generation);
        write_key(encoder, 9);
        encoder.write_byte_string(&self.session_id);
        write_key(encoder, 10);
        encoder.write_text_string(&self.endpoint);
        write_key(encoder, 11);
        encoder.write_byte_string(&self.certificate_sha256);
        write_key(encoder, 12);
        encoder.write_byte_string(&self.certificate_der);
        write_key(encoder, 13);
        encoder.write_array_header(self.capabilities.len() as u64);
        for capability in &self.capabilities {
            encoder.write_text_string(capability);
        }
        if include_proof {
            write_key(encoder, 14);
            encoder.write_byte_string(&self.readiness_proof);
        }
        Ok(())
    }
}

impl fmt::Debug for ProtectedReadyV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProtectedReadyV1")
            .field("protocol_schema_version", &self.protocol_schema_version)
            .field("launch_generation", &self.launch_generation)
            .field("protected_fields", &"<redacted>")
            .finish()
    }
}

impl DeterministicCodec for ProtectedReadyV1 {
    const MESSAGE_TYPE_ID: u32 = 2;

    fn encode(&self, encoder: &mut CborEncoder) -> Result<(), EncodeError> {
        self.encode_fields(encoder, true)
    }

    fn decode(type_id: u32, decoder: &mut CborDecoder<'_>) -> Result<Self, DecodeError> {
        if type_id != Self::MESSAGE_TYPE_ID || decoder.read_map_header(15)? != 15 {
            return Err(DecodeError::UnknownMessageType { type_id });
        }
        expect_key(decoder, 0)?;
        expect_message_type(decoder, Self::MESSAGE_TYPE_ID)?;
        expect_key(decoder, 1)?;
        if decoder.read_unsigned(u64::from(u32::MAX))? != u64::from(PROTOCOL_SCHEMA_VERSION) {
            return Err(DecodeError::UnknownField { key: 1 });
        }
        expect_key(decoder, 2)?;
        let launch_authority_id = decode_fixed::<16>(decoder)?;
        expect_key(decoder, 3)?;
        let desktop_host_instance_id = decode_fixed::<16>(decoder)?;
        expect_key(decoder, 4)?;
        let executable = decode_executable(decoder)?;
        expect_key(decoder, 5)?;
        let profile = decode_profile(decoder)?;
        expect_key(decoder, 6)?;
        let stable = decode_stable(decoder)?;
        expect_key(decoder, 7)?;
        let daemon_instance_id = decode_fixed::<16>(decoder)?;
        expect_key(decoder, 8)?;
        let launch_generation = decoder.read_unsigned(u64::MAX)?;
        expect_key(decoder, 9)?;
        let session_id = decode_fixed::<16>(decoder)?;
        expect_key(decoder, 10)?;
        let endpoint = decoder.read_text_string(MAX_TEXT_BYTES)?.to_owned();
        expect_key(decoder, 11)?;
        let certificate_sha256 = decode_fixed::<32>(decoder)?;
        expect_key(decoder, 12)?;
        let certificate_der = decoder
            .read_byte_string(MAX_CERTIFICATE_DER_BYTES)?
            .to_vec();
        expect_key(decoder, 13)?;
        let count = usize::try_from(decoder.read_array_header(MAX_CAPABILITIES as u32)?)
            .map_err(|_| DecodeError::UnknownField { key: 13 })?;
        let mut capabilities = Vec::with_capacity(count);
        for _ in 0..count {
            capabilities.push(decoder.read_text_string(MAX_PROFILE_ID_BYTES)?.to_owned());
        }
        expect_key(decoder, 14)?;
        let readiness_proof = decode_fixed::<32>(decoder)?;
        let mut value = Self::new(
            launch_authority_id,
            desktop_host_instance_id,
            executable,
            profile,
            stable,
            daemon_instance_id,
            launch_generation,
            session_id,
            endpoint,
            certificate_sha256,
            certificate_der,
            capabilities,
        )
        .map_err(|_| DecodeError::UnknownField { key: 14 })?;
        value.readiness_proof = readiness_proof;
        Ok(value)
    }
}

/// Protocol V2 protected launch request with an authenticated provider binding.
///
/// The nested V1 request is a compatibility core only. The outer V2 message
/// type and schema are the negotiated wire contract, so a V1 reader rejects
/// the frame instead of silently discarding the provider binding.
#[derive(Clone, Eq, PartialEq)]
pub struct ProtectedLaunchRequestV2 {
    protocol_schema_version: u32,
    compatibility_request: ProtectedLaunchRequestV1,
    provider_binding: ProviderActivationBindingV1,
}

impl ProtectedLaunchRequestV2 {
    /// Promotes one protected V1 launch core into the provider-bound V2 wire.
    pub fn new(
        compatibility_request: ProtectedLaunchRequestV1,
        provider_binding: ProviderActivationBindingV1,
    ) -> Result<Self, LaunchAuthorityError> {
        if compatibility_request.profile.transport_profile_id
            != PROTECTED_BUNDLED_TRANSPORT_PROFILE_ID
        {
            return Err(LaunchAuthorityError::DowngradedExternalProfile);
        }
        Ok(Self {
            protocol_schema_version: PROTOCOL_SCHEMA_VERSION_V2,
            compatibility_request,
            provider_binding,
        })
    }

    /// Validates the launch core and exact expected provider mode/profile.
    pub fn validate(
        &self,
        now_unix_millis: u64,
        expected: &LaunchAuthorityValidationV1<'_>,
        expected_provider: &ProviderActivationBindingV1,
    ) -> Result<(), LaunchAuthorityError> {
        self.compatibility_request
            .validate(now_unix_millis, expected)?;
        self.provider_binding.verify_exact(expected_provider)
    }

    /// Rechecks the launch deadline without consuming the provider binding.
    pub fn validate_freshness(&self, now_unix_millis: u64) -> Result<(), LaunchAuthorityError> {
        if self.protocol_schema_version != PROTOCOL_SCHEMA_VERSION_V2 {
            return Err(LaunchAuthorityError::StaleLaunchAuthority);
        }
        self.compatibility_request
            .validate_freshness(now_unix_millis)
    }

    /// Encodes the strict bounded V2 launch frame.
    pub fn encode_frame(&self) -> Result<Vec<u8>, EncodeError> {
        encode_codec_frame(
            self,
            &FrameLimits {
                max_frame_bytes: MAX_FRAME_BYTES,
            },
        )
    }

    /// Decodes only the exact V2 launch frame.
    pub fn decode_frame(frame: &[u8]) -> Result<Self, DecodeError> {
        decode_codec_frame(frame, &decode_limits())
    }

    /// Returns the reader-only V1 core used by first-activation migration.
    #[must_use]
    pub const fn compatibility_request(&self) -> &ProtectedLaunchRequestV1 {
        &self.compatibility_request
    }

    #[must_use]
    pub const fn provider_binding(&self) -> &ProviderActivationBindingV1 {
        &self.provider_binding
    }

    #[must_use]
    pub const fn launch_authority_id(&self) -> [u8; 16] {
        self.compatibility_request.launch_authority_id()
    }

    #[must_use]
    pub const fn desktop_host_instance_id(&self) -> [u8; 16] {
        self.compatibility_request.desktop_host_instance_id()
    }

    #[must_use]
    pub fn principal_id(&self) -> &str {
        self.compatibility_request.principal_id()
    }

    #[must_use]
    pub const fn profile(&self) -> &ProtectedRuntimeProfileV1 {
        self.compatibility_request.profile()
    }

    #[must_use]
    pub const fn executable(&self) -> &ExecutableIdentityV1 {
        self.compatibility_request.executable()
    }

    #[must_use]
    pub fn runtime_root(&self) -> &std::path::Path {
        self.compatibility_request.runtime_root()
    }

    #[must_use]
    pub const fn activation_disposition(&self) -> &ActivationDispositionV1 {
        self.compatibility_request.activation_disposition()
    }

    #[must_use]
    pub fn derive_keys(&self) -> ProtectedActivationKeys {
        self.compatibility_request.derive_keys()
    }

    pub fn derive_keys_and_forget(&mut self) -> ProtectedActivationKeys {
        self.compatibility_request.derive_keys_and_forget()
    }
}

impl fmt::Debug for ProtectedLaunchRequestV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProtectedLaunchRequestV2")
            .field("protocol_schema_version", &self.protocol_schema_version)
            .field("provider_binding", &self.provider_binding)
            .field("protected_fields", &"<redacted>")
            .finish()
    }
}

impl DeterministicCodec for ProtectedLaunchRequestV2 {
    const MESSAGE_TYPE_ID: u32 = 21;

    fn encode(&self, encoder: &mut CborEncoder) -> Result<(), EncodeError> {
        encoder.write_map_header(4);
        write_key(encoder, 0);
        encoder.write_unsigned(u64::from(Self::MESSAGE_TYPE_ID));
        write_key(encoder, 1);
        encoder.write_unsigned(u64::from(self.protocol_schema_version));
        write_key(encoder, 2);
        self.compatibility_request.encode(encoder)?;
        write_key(encoder, 3);
        encode_provider_binding(encoder, &self.provider_binding);
        Ok(())
    }

    fn decode(type_id: u32, decoder: &mut CborDecoder<'_>) -> Result<Self, DecodeError> {
        if type_id != Self::MESSAGE_TYPE_ID || decoder.read_map_header(4)? != 4 {
            return Err(DecodeError::UnknownMessageType { type_id });
        }
        expect_key(decoder, 0)?;
        expect_message_type(decoder, Self::MESSAGE_TYPE_ID)?;
        expect_schema_version(decoder, PROTOCOL_SCHEMA_VERSION_V2)?;
        expect_key(decoder, 2)?;
        let compatibility_request =
            ProtectedLaunchRequestV1::decode(ProtectedLaunchRequestV1::MESSAGE_TYPE_ID, decoder)?;
        expect_key(decoder, 3)?;
        let provider_binding = decode_provider_binding(decoder)?;
        Self::new(compatibility_request, provider_binding)
            .map_err(|_| DecodeError::UnknownField { key: 3 })
    }
}

/// Exact V2 launch tuple required by renewal and shutdown ownership proofs.
#[derive(Clone, Eq, PartialEq)]
pub struct ProtectedOwnedLaunchV2 {
    compatibility_owned_launch: ProtectedOwnedLaunchV1,
    provider_binding: ProviderActivationBindingV1,
}

impl ProtectedOwnedLaunchV2 {
    pub fn new(
        compatibility_owned_launch: ProtectedOwnedLaunchV1,
        provider_binding: ProviderActivationBindingV1,
    ) -> Result<Self, LaunchAuthorityError> {
        if compatibility_owned_launch.profile.transport_profile_id
            != PROTECTED_BUNDLED_TRANSPORT_PROFILE_ID
        {
            return Err(LaunchAuthorityError::DowngradedExternalProfile);
        }
        Ok(Self {
            compatibility_owned_launch,
            provider_binding,
        })
    }

    #[must_use]
    pub const fn compatibility_owned_launch(&self) -> &ProtectedOwnedLaunchV1 {
        &self.compatibility_owned_launch
    }

    #[must_use]
    pub const fn provider_binding(&self) -> &ProviderActivationBindingV1 {
        &self.provider_binding
    }

    #[must_use]
    pub const fn launch_authority_id(&self) -> &[u8; 16] {
        self.compatibility_owned_launch.launch_authority_id()
    }

    #[must_use]
    pub const fn desktop_host_instance_id(&self) -> &[u8; 16] {
        self.compatibility_owned_launch.desktop_host_instance_id()
    }

    #[must_use]
    pub const fn daemon_instance_id(&self) -> &[u8; 16] {
        self.compatibility_owned_launch.daemon_instance_id()
    }

    #[must_use]
    pub const fn launch_generation(&self) -> u64 {
        self.compatibility_owned_launch.launch_generation()
    }

    #[must_use]
    pub const fn session_id(&self) -> &[u8; 16] {
        self.compatibility_owned_launch.session_id()
    }

    fn verify_exact(&self, expected: &Self) -> Result<(), LaunchAuthorityError> {
        if self.compatibility_owned_launch != expected.compatibility_owned_launch {
            return Err(LaunchAuthorityError::OwnershipMismatch);
        }
        self.provider_binding
            .verify_exact(&expected.provider_binding)
    }
}

impl fmt::Debug for ProtectedOwnedLaunchV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProtectedOwnedLaunchV2")
            .field("launch_generation", &self.launch_generation())
            .field("provider_binding", &self.provider_binding)
            .field("protected_fields", &"<redacted>")
            .finish()
    }
}

/// Authenticated V2 readiness with exact provider mode/profile binding.
#[derive(Clone, Eq, PartialEq)]
pub struct ProtectedReadyV2 {
    protocol_schema_version: u32,
    compatibility_ready: ProtectedReadyV1,
    provider_binding: ProviderActivationBindingV1,
    readiness_proof: [u8; 32],
}

impl ProtectedReadyV2 {
    pub fn new(
        compatibility_ready: ProtectedReadyV1,
        provider_binding: ProviderActivationBindingV1,
    ) -> Result<Self, LaunchAuthorityError> {
        if compatibility_ready.profile.transport_profile_id
            != PROTECTED_BUNDLED_TRANSPORT_PROFILE_ID
        {
            return Err(LaunchAuthorityError::DowngradedExternalProfile);
        }
        Ok(Self {
            protocol_schema_version: PROTOCOL_SCHEMA_VERSION_V2,
            compatibility_ready,
            provider_binding,
            readiness_proof: [0; 32],
        })
    }

    pub fn sign(&mut self, keys: &ProtectedActivationKeys) {
        self.compatibility_ready.sign(keys);
        self.readiness_proof = authenticated_mac_version(
            keys.readiness_key(),
            READINESS_DOMAIN_V2,
            PROTOCOL_SCHEMA_VERSION_V2,
            &self.unsigned_payload(),
        );
    }

    pub fn verify_exact(
        &self,
        request: &ProtectedLaunchRequestV2,
        keys: &ProtectedActivationKeys,
    ) -> Result<(), LaunchAuthorityError> {
        self.provider_binding
            .verify_exact(request.provider_binding())?;
        self.compatibility_ready
            .verify_exact(request.compatibility_request(), keys)?;
        let expected = authenticated_mac_version(
            keys.readiness_key(),
            READINESS_DOMAIN_V2,
            PROTOCOL_SCHEMA_VERSION_V2,
            &self.unsigned_payload(),
        );
        if !bool::from(expected.ct_eq(&self.readiness_proof)) {
            return Err(LaunchAuthorityError::ReadinessProofMismatch);
        }
        Ok(())
    }

    pub fn encode_frame(&self) -> Result<Vec<u8>, EncodeError> {
        encode_codec_frame(
            self,
            &FrameLimits {
                max_frame_bytes: MAX_FRAME_BYTES,
            },
        )
    }

    pub fn decode_frame(frame: &[u8]) -> Result<Self, DecodeError> {
        decode_codec_frame(frame, &decode_limits())
    }

    #[must_use]
    pub const fn compatibility_ready(&self) -> &ProtectedReadyV1 {
        &self.compatibility_ready
    }

    #[must_use]
    pub const fn provider_binding(&self) -> &ProviderActivationBindingV1 {
        &self.provider_binding
    }

    #[must_use]
    pub const fn stable(&self) -> &StableRuntimeBindingV1 {
        self.compatibility_ready.stable()
    }

    #[must_use]
    pub const fn profile(&self) -> &ProtectedRuntimeProfileV1 {
        self.compatibility_ready.profile()
    }

    #[must_use]
    pub const fn executable(&self) -> &ExecutableIdentityV1 {
        self.compatibility_ready.executable()
    }

    #[must_use]
    pub const fn daemon_instance_id(&self) -> &[u8; 16] {
        self.compatibility_ready.daemon_instance_id()
    }

    #[must_use]
    pub const fn launch_generation(&self) -> u64 {
        self.compatibility_ready.launch_generation()
    }

    #[must_use]
    pub const fn session_id(&self) -> &[u8; 16] {
        self.compatibility_ready.session_id()
    }

    #[must_use]
    pub fn endpoint(&self) -> &str {
        self.compatibility_ready.endpoint()
    }

    #[must_use]
    pub const fn certificate_sha256(&self) -> &[u8; 32] {
        self.compatibility_ready.certificate_sha256()
    }

    #[must_use]
    pub fn certificate_der(&self) -> &[u8] {
        self.compatibility_ready.certificate_der()
    }

    #[must_use]
    pub fn capabilities(&self) -> &[String] {
        self.compatibility_ready.capabilities()
    }

    #[must_use]
    pub fn owned_launch(&self) -> ProtectedOwnedLaunchV2 {
        ProtectedOwnedLaunchV2::new(
            self.compatibility_ready.owned_launch(),
            self.provider_binding.clone(),
        )
        .expect("validated V2 readiness has a valid owned-launch tuple")
    }

    fn unsigned_payload(&self) -> Vec<u8> {
        let mut encoder = CborEncoder::new();
        self.encode_fields(&mut encoder, false)
            .expect("validated V2 readiness is encodable");
        encoder.into_bytes()
    }

    fn encode_fields(
        &self,
        encoder: &mut CborEncoder,
        include_proof: bool,
    ) -> Result<(), EncodeError> {
        encoder.write_map_header(if include_proof { 5 } else { 4 });
        write_key(encoder, 0);
        encoder.write_unsigned(u64::from(Self::MESSAGE_TYPE_ID));
        write_key(encoder, 1);
        encoder.write_unsigned(u64::from(self.protocol_schema_version));
        write_key(encoder, 2);
        self.compatibility_ready.encode(encoder)?;
        write_key(encoder, 3);
        encode_provider_binding(encoder, &self.provider_binding);
        if include_proof {
            write_key(encoder, 4);
            encoder.write_byte_string(&self.readiness_proof);
        }
        Ok(())
    }
}

impl fmt::Debug for ProtectedReadyV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProtectedReadyV2")
            .field("launch_generation", &self.launch_generation())
            .field("provider_binding", &self.provider_binding)
            .field("protected_fields", &"<redacted>")
            .finish()
    }
}

impl DeterministicCodec for ProtectedReadyV2 {
    const MESSAGE_TYPE_ID: u32 = 22;

    fn encode(&self, encoder: &mut CborEncoder) -> Result<(), EncodeError> {
        self.encode_fields(encoder, true)
    }

    fn decode(type_id: u32, decoder: &mut CborDecoder<'_>) -> Result<Self, DecodeError> {
        if type_id != Self::MESSAGE_TYPE_ID || decoder.read_map_header(5)? != 5 {
            return Err(DecodeError::UnknownMessageType { type_id });
        }
        expect_key(decoder, 0)?;
        expect_message_type(decoder, Self::MESSAGE_TYPE_ID)?;
        expect_schema_version(decoder, PROTOCOL_SCHEMA_VERSION_V2)?;
        expect_key(decoder, 2)?;
        let compatibility_ready =
            ProtectedReadyV1::decode(ProtectedReadyV1::MESSAGE_TYPE_ID, decoder)?;
        expect_key(decoder, 3)?;
        let provider_binding = decode_provider_binding(decoder)?;
        expect_key(decoder, 4)?;
        let readiness_proof = decode_fixed::<32>(decoder)?;
        let mut value = Self::new(compatibility_ready, provider_binding)
            .map_err(|_| DecodeError::UnknownField { key: 3 })?;
        value.readiness_proof = readiness_proof;
        Ok(value)
    }
}

/// Monotonic V2 protected request for one replacement HTTP session authority.
#[derive(Clone, Eq, PartialEq)]
pub struct ProtectedRenewRequestV2 {
    protocol_schema_version: u32,
    owned_launch: ProtectedOwnedLaunchV2,
    sequence: u64,
    nonce: [u8; 32],
    proof: [u8; 32],
}

impl ProtectedRenewRequestV2 {
    pub fn new(
        owned_launch: ProtectedOwnedLaunchV2,
        sequence: u64,
        nonce: [u8; 32],
    ) -> Result<Self, LaunchAuthorityError> {
        if sequence == 0 || nonce == [0; 32] {
            return Err(LaunchAuthorityError::RenewalReplay);
        }
        Ok(Self {
            protocol_schema_version: PROTOCOL_SCHEMA_VERSION_V2,
            owned_launch,
            sequence,
            nonce,
            proof: [0; 32],
        })
    }

    pub fn sign(&mut self, keys: &ProtectedActivationKeys) {
        self.proof = authenticated_mac_version(
            keys.renewal_key_ref(),
            RENEW_DOMAIN_V2,
            PROTOCOL_SCHEMA_VERSION_V2,
            &self.unsigned_payload(),
        );
    }

    pub fn verify_exact(
        &self,
        expected: &ProtectedOwnedLaunchV2,
        last_sequence: u64,
        keys: &ProtectedActivationKeys,
    ) -> Result<(), LaunchAuthorityError> {
        self.owned_launch.verify_exact(expected)?;
        let next_sequence = last_sequence
            .checked_add(1)
            .ok_or(LaunchAuthorityError::RenewalReplay)?;
        if self.sequence != next_sequence || self.nonce == [0; 32] {
            return Err(LaunchAuthorityError::RenewalReplay);
        }
        let expected_proof = authenticated_mac_version(
            keys.renewal_key_ref(),
            RENEW_DOMAIN_V2,
            PROTOCOL_SCHEMA_VERSION_V2,
            &self.unsigned_payload(),
        );
        if !bool::from(expected_proof.ct_eq(&self.proof)) {
            return Err(LaunchAuthorityError::ReadinessProofMismatch);
        }
        Ok(())
    }

    #[must_use]
    pub const fn owned_launch(&self) -> &ProtectedOwnedLaunchV2 {
        &self.owned_launch
    }

    #[must_use]
    pub const fn sequence(&self) -> u64 {
        self.sequence
    }

    #[must_use]
    pub const fn nonce(&self) -> &[u8; 32] {
        &self.nonce
    }

    pub fn encode_frame(&self) -> Result<Vec<u8>, EncodeError> {
        encode_codec_frame(
            self,
            &FrameLimits {
                max_frame_bytes: MAX_FRAME_BYTES,
            },
        )
    }

    pub fn decode_frame(frame: &[u8]) -> Result<Self, DecodeError> {
        decode_codec_frame(frame, &decode_limits())
    }

    fn unsigned_payload(&self) -> Vec<u8> {
        let mut encoder = CborEncoder::new();
        self.encode_fields(&mut encoder, false);
        encoder.into_bytes()
    }

    fn encode_fields(&self, encoder: &mut CborEncoder, include_proof: bool) {
        encoder.write_map_header(if include_proof { 6 } else { 5 });
        write_key(encoder, 0);
        encoder.write_unsigned(u64::from(Self::MESSAGE_TYPE_ID));
        write_key(encoder, 1);
        encoder.write_unsigned(u64::from(self.protocol_schema_version));
        write_key(encoder, 2);
        encode_owned_launch_v2(encoder, &self.owned_launch);
        write_key(encoder, 3);
        encoder.write_unsigned(self.sequence);
        write_key(encoder, 4);
        encoder.write_byte_string(&self.nonce);
        if include_proof {
            write_key(encoder, 5);
            encoder.write_byte_string(&self.proof);
        }
    }
}

impl fmt::Debug for ProtectedRenewRequestV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProtectedRenewRequestV2")
            .field("sequence", &self.sequence)
            .field("provider_binding", self.owned_launch.provider_binding())
            .field("protected_fields", &"<redacted>")
            .finish()
    }
}

impl DeterministicCodec for ProtectedRenewRequestV2 {
    const MESSAGE_TYPE_ID: u32 = 23;

    fn encode(&self, encoder: &mut CborEncoder) -> Result<(), EncodeError> {
        self.encode_fields(encoder, true);
        Ok(())
    }

    fn decode(type_id: u32, decoder: &mut CborDecoder<'_>) -> Result<Self, DecodeError> {
        if type_id != Self::MESSAGE_TYPE_ID || decoder.read_map_header(6)? != 6 {
            return Err(DecodeError::UnknownMessageType { type_id });
        }
        expect_key(decoder, 0)?;
        expect_message_type(decoder, Self::MESSAGE_TYPE_ID)?;
        expect_schema_version(decoder, PROTOCOL_SCHEMA_VERSION_V2)?;
        expect_key(decoder, 2)?;
        let owned_launch = decode_owned_launch_v2(decoder)?;
        expect_key(decoder, 3)?;
        let sequence = decoder.read_unsigned(u64::MAX)?;
        expect_key(decoder, 4)?;
        let nonce = decode_fixed::<32>(decoder)?;
        expect_key(decoder, 5)?;
        let proof = decode_fixed::<32>(decoder)?;
        let mut value = Self::new(owned_launch, sequence, nonce)
            .map_err(|_| DecodeError::UnknownField { key: 4 })?;
        value.proof = proof;
        Ok(value)
    }
}

/// One-time V2 protected bootstrap ticket retaining the provider binding.
#[derive(Clone, Eq, PartialEq)]
pub struct ProtectedRenewTicketV2 {
    protocol_schema_version: u32,
    owned_launch: ProtectedOwnedLaunchV2,
    sequence: u64,
    nonce: [u8; 32],
    next_session_id: [u8; 16],
    bootstrap_ticket: [u8; 32],
    issued_at_monotonic_millis: u64,
    expires_at_monotonic_millis: u64,
    proof: [u8; 32],
}

impl ProtectedRenewTicketV2 {
    pub fn new(
        request: &ProtectedRenewRequestV2,
        next_session_id: [u8; 16],
        bootstrap_ticket: [u8; 32],
        issued_at_monotonic_millis: u64,
        expires_at_monotonic_millis: u64,
    ) -> Result<Self, LaunchAuthorityError> {
        if validate_uuid_v7_bytes(&next_session_id).is_err()
            || next_session_id == *request.owned_launch.session_id()
            || next_session_id == *request.owned_launch.daemon_instance_id()
            || bootstrap_ticket == [0; 32]
            || expires_at_monotonic_millis <= issued_at_monotonic_millis
            || expires_at_monotonic_millis.saturating_sub(issued_at_monotonic_millis)
                > MAX_LAUNCH_TTL_MILLIS
        {
            return Err(LaunchAuthorityError::RenewalUnavailable);
        }
        Ok(Self {
            protocol_schema_version: PROTOCOL_SCHEMA_VERSION_V2,
            owned_launch: request.owned_launch.clone(),
            sequence: request.sequence,
            nonce: request.nonce,
            next_session_id,
            bootstrap_ticket,
            issued_at_monotonic_millis,
            expires_at_monotonic_millis,
            proof: [0; 32],
        })
    }

    pub fn sign(&mut self, keys: &ProtectedActivationKeys) {
        self.proof = authenticated_mac_version(
            keys.renewal_key_ref(),
            RENEW_DOMAIN_V2,
            PROTOCOL_SCHEMA_VERSION_V2,
            &self.unsigned_payload(),
        );
    }

    pub fn verify_exact(
        &self,
        request: &ProtectedRenewRequestV2,
        keys: &ProtectedActivationKeys,
    ) -> Result<(), LaunchAuthorityError> {
        self.owned_launch.verify_exact(&request.owned_launch)?;
        if self.sequence != request.sequence || self.nonce != request.nonce {
            return Err(LaunchAuthorityError::RenewalReplay);
        }
        if validate_uuid_v7_bytes(&self.next_session_id).is_err()
            || self.next_session_id == *self.owned_launch.session_id()
            || self.next_session_id == *self.owned_launch.daemon_instance_id()
            || self.bootstrap_ticket == [0; 32]
            || self.expires_at_monotonic_millis <= self.issued_at_monotonic_millis
            || self
                .expires_at_monotonic_millis
                .saturating_sub(self.issued_at_monotonic_millis)
                > MAX_LAUNCH_TTL_MILLIS
        {
            return Err(LaunchAuthorityError::RenewalUnavailable);
        }
        let expected = authenticated_mac_version(
            keys.renewal_key_ref(),
            RENEW_DOMAIN_V2,
            PROTOCOL_SCHEMA_VERSION_V2,
            &self.unsigned_payload(),
        );
        if !bool::from(expected.ct_eq(&self.proof)) {
            return Err(LaunchAuthorityError::ReadinessProofMismatch);
        }
        Ok(())
    }

    #[must_use]
    pub const fn next_session_id(&self) -> &[u8; 16] {
        &self.next_session_id
    }

    #[must_use]
    pub fn bootstrap_ticket(&self) -> Zeroizing<[u8; 32]> {
        Zeroizing::new(self.bootstrap_ticket)
    }

    #[must_use]
    pub const fn issued_at_monotonic_millis(&self) -> u64 {
        self.issued_at_monotonic_millis
    }

    #[must_use]
    pub const fn expires_at_monotonic_millis(&self) -> u64 {
        self.expires_at_monotonic_millis
    }

    #[must_use]
    pub fn next_owned_launch(&self) -> ProtectedOwnedLaunchV2 {
        let base = &self.owned_launch.compatibility_owned_launch;
        let next = ProtectedOwnedLaunchV1::new(
            base.launch_authority_id,
            base.desktop_host_instance_id,
            base.executable.clone(),
            base.profile.clone(),
            base.stable.clone(),
            base.daemon_instance_id,
            base.launch_generation,
            self.next_session_id,
        )
        .expect("validated V2 ticket has a valid next session");
        ProtectedOwnedLaunchV2::new(next, self.owned_launch.provider_binding.clone())
            .expect("validated V2 ticket retains a valid provider binding")
    }

    pub fn encode_frame(&self) -> Result<Vec<u8>, EncodeError> {
        encode_codec_frame(
            self,
            &FrameLimits {
                max_frame_bytes: MAX_FRAME_BYTES,
            },
        )
    }

    pub fn decode_frame(frame: &[u8]) -> Result<Self, DecodeError> {
        decode_codec_frame(frame, &decode_limits())
    }

    fn unsigned_payload(&self) -> Vec<u8> {
        let mut encoder = CborEncoder::new();
        self.encode_fields(&mut encoder, false);
        encoder.into_bytes()
    }

    fn encode_fields(&self, encoder: &mut CborEncoder, include_proof: bool) {
        encoder.write_map_header(if include_proof { 10 } else { 9 });
        write_key(encoder, 0);
        encoder.write_unsigned(u64::from(Self::MESSAGE_TYPE_ID));
        write_key(encoder, 1);
        encoder.write_unsigned(u64::from(self.protocol_schema_version));
        write_key(encoder, 2);
        encode_owned_launch_v2(encoder, &self.owned_launch);
        write_key(encoder, 3);
        encoder.write_unsigned(self.sequence);
        write_key(encoder, 4);
        encoder.write_byte_string(&self.nonce);
        write_key(encoder, 5);
        encoder.write_byte_string(&self.next_session_id);
        write_key(encoder, 6);
        encoder.write_byte_string(&self.bootstrap_ticket);
        write_key(encoder, 7);
        encoder.write_unsigned(self.issued_at_monotonic_millis);
        write_key(encoder, 8);
        encoder.write_unsigned(self.expires_at_monotonic_millis);
        if include_proof {
            write_key(encoder, 9);
            encoder.write_byte_string(&self.proof);
        }
    }
}

impl fmt::Debug for ProtectedRenewTicketV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProtectedRenewTicketV2")
            .field("sequence", &self.sequence)
            .field(
                "expires_at_monotonic_millis",
                &self.expires_at_monotonic_millis,
            )
            .field("provider_binding", self.owned_launch.provider_binding())
            .field("protected_fields", &"<redacted>")
            .finish()
    }
}

impl Drop for ProtectedRenewTicketV2 {
    fn drop(&mut self) {
        self.bootstrap_ticket.zeroize();
    }
}

impl DeterministicCodec for ProtectedRenewTicketV2 {
    const MESSAGE_TYPE_ID: u32 = 24;

    fn encode(&self, encoder: &mut CborEncoder) -> Result<(), EncodeError> {
        self.encode_fields(encoder, true);
        Ok(())
    }

    fn decode(type_id: u32, decoder: &mut CborDecoder<'_>) -> Result<Self, DecodeError> {
        if type_id != Self::MESSAGE_TYPE_ID || decoder.read_map_header(10)? != 10 {
            return Err(DecodeError::UnknownMessageType { type_id });
        }
        expect_key(decoder, 0)?;
        expect_message_type(decoder, Self::MESSAGE_TYPE_ID)?;
        expect_schema_version(decoder, PROTOCOL_SCHEMA_VERSION_V2)?;
        expect_key(decoder, 2)?;
        let owned_launch = decode_owned_launch_v2(decoder)?;
        expect_key(decoder, 3)?;
        let sequence = decoder.read_unsigned(u64::MAX)?;
        expect_key(decoder, 4)?;
        let nonce = decode_fixed::<32>(decoder)?;
        expect_key(decoder, 5)?;
        let next_session_id = decode_fixed::<16>(decoder)?;
        expect_key(decoder, 6)?;
        let bootstrap_ticket = decode_fixed::<32>(decoder)?;
        expect_key(decoder, 7)?;
        let issued_at_monotonic_millis = decoder.read_unsigned(u64::MAX)?;
        expect_key(decoder, 8)?;
        let expires_at_monotonic_millis = decoder.read_unsigned(u64::MAX)?;
        expect_key(decoder, 9)?;
        let proof = decode_fixed::<32>(decoder)?;
        let request = ProtectedRenewRequestV2 {
            protocol_schema_version: PROTOCOL_SCHEMA_VERSION_V2,
            owned_launch,
            sequence,
            nonce,
            proof: [1; 32],
        };
        let mut value = Self::new(
            &request,
            next_session_id,
            bootstrap_ticket,
            issued_at_monotonic_millis,
            expires_at_monotonic_millis,
        )
        .map_err(|_| DecodeError::UnknownField { key: 7 })?;
        value.proof = proof;
        Ok(value)
    }
}

/// HMAC-authenticated V2 shutdown request for an exact provider-bound launch.
#[derive(Clone, Eq, PartialEq)]
pub struct ProtectedShutdownV2 {
    protocol_schema_version: u32,
    owned_launch: ProtectedOwnedLaunchV2,
    proof: [u8; 32],
}

impl ProtectedShutdownV2 {
    #[must_use]
    pub const fn new(owned_launch: ProtectedOwnedLaunchV2) -> Self {
        Self {
            protocol_schema_version: PROTOCOL_SCHEMA_VERSION_V2,
            owned_launch,
            proof: [0; 32],
        }
    }

    pub fn sign(&mut self, keys: &ProtectedActivationKeys) {
        self.proof = authenticated_mac_version(
            keys.shutdown_key_ref(),
            SHUTDOWN_DOMAIN_V2,
            PROTOCOL_SCHEMA_VERSION_V2,
            &self.unsigned_payload(),
        );
    }

    pub fn verify_exact(
        &self,
        expected: &ProtectedOwnedLaunchV2,
        keys: &ProtectedActivationKeys,
    ) -> Result<(), LaunchAuthorityError> {
        self.owned_launch.verify_exact(expected)?;
        let proof = authenticated_mac_version(
            keys.shutdown_key_ref(),
            SHUTDOWN_DOMAIN_V2,
            PROTOCOL_SCHEMA_VERSION_V2,
            &self.unsigned_payload(),
        );
        if !bool::from(proof.ct_eq(&self.proof)) {
            return Err(LaunchAuthorityError::ReadinessProofMismatch);
        }
        Ok(())
    }

    #[must_use]
    pub const fn owned_launch(&self) -> &ProtectedOwnedLaunchV2 {
        &self.owned_launch
    }

    pub fn encode_frame(&self) -> Result<Vec<u8>, EncodeError> {
        encode_codec_frame(
            self,
            &FrameLimits {
                max_frame_bytes: MAX_FRAME_BYTES,
            },
        )
    }

    pub fn decode_frame(frame: &[u8]) -> Result<Self, DecodeError> {
        decode_codec_frame(frame, &decode_limits())
    }

    fn unsigned_payload(&self) -> Vec<u8> {
        let mut encoder = CborEncoder::new();
        self.encode_fields(&mut encoder, false);
        encoder.into_bytes()
    }

    fn encode_fields(&self, encoder: &mut CborEncoder, include_proof: bool) {
        encoder.write_map_header(if include_proof { 4 } else { 3 });
        write_key(encoder, 0);
        encoder.write_unsigned(u64::from(Self::MESSAGE_TYPE_ID));
        write_key(encoder, 1);
        encoder.write_unsigned(u64::from(self.protocol_schema_version));
        write_key(encoder, 2);
        encode_owned_launch_v2(encoder, &self.owned_launch);
        if include_proof {
            write_key(encoder, 3);
            encoder.write_byte_string(&self.proof);
        }
    }
}

impl fmt::Debug for ProtectedShutdownV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProtectedShutdownV2")
            .field("provider_binding", self.owned_launch.provider_binding())
            .field("protected_fields", &"<redacted>")
            .finish()
    }
}

impl DeterministicCodec for ProtectedShutdownV2 {
    const MESSAGE_TYPE_ID: u32 = 25;

    fn encode(&self, encoder: &mut CborEncoder) -> Result<(), EncodeError> {
        self.encode_fields(encoder, true);
        Ok(())
    }

    fn decode(type_id: u32, decoder: &mut CborDecoder<'_>) -> Result<Self, DecodeError> {
        if type_id != Self::MESSAGE_TYPE_ID || decoder.read_map_header(4)? != 4 {
            return Err(DecodeError::UnknownMessageType { type_id });
        }
        expect_key(decoder, 0)?;
        expect_message_type(decoder, Self::MESSAGE_TYPE_ID)?;
        expect_schema_version(decoder, PROTOCOL_SCHEMA_VERSION_V2)?;
        expect_key(decoder, 2)?;
        let owned_launch = decode_owned_launch_v2(decoder)?;
        expect_key(decoder, 3)?;
        let proof = decode_fixed::<32>(decoder)?;
        Ok(Self {
            protocol_schema_version: PROTOCOL_SCHEMA_VERSION_V2,
            owned_launch,
            proof,
        })
    }
}

/// V2 acknowledgement that the exact provider-bound launch accepted shutdown.
#[derive(Clone, Eq, PartialEq)]
pub struct ProtectedShutdownAckV2 {
    protocol_schema_version: u32,
    owned_launch: ProtectedOwnedLaunchV2,
    graceful: bool,
    proof: [u8; 32],
}

impl ProtectedShutdownAckV2 {
    #[must_use]
    pub const fn new(owned_launch: ProtectedOwnedLaunchV2, graceful: bool) -> Self {
        Self {
            protocol_schema_version: PROTOCOL_SCHEMA_VERSION_V2,
            owned_launch,
            graceful,
            proof: [0; 32],
        }
    }

    pub fn sign(&mut self, keys: &ProtectedActivationKeys) {
        self.proof = authenticated_mac_version(
            keys.shutdown_key_ref(),
            SHUTDOWN_DOMAIN_V2,
            PROTOCOL_SCHEMA_VERSION_V2,
            &self.unsigned_payload(),
        );
    }

    pub fn verify_exact(
        &self,
        expected: &ProtectedOwnedLaunchV2,
        keys: &ProtectedActivationKeys,
    ) -> Result<(), LaunchAuthorityError> {
        self.owned_launch.verify_exact(expected)?;
        let proof = authenticated_mac_version(
            keys.shutdown_key_ref(),
            SHUTDOWN_DOMAIN_V2,
            PROTOCOL_SCHEMA_VERSION_V2,
            &self.unsigned_payload(),
        );
        if !bool::from(proof.ct_eq(&self.proof)) {
            return Err(LaunchAuthorityError::ReadinessProofMismatch);
        }
        Ok(())
    }

    #[must_use]
    pub const fn graceful(&self) -> bool {
        self.graceful
    }

    pub fn encode_frame(&self) -> Result<Vec<u8>, EncodeError> {
        encode_codec_frame(
            self,
            &FrameLimits {
                max_frame_bytes: MAX_FRAME_BYTES,
            },
        )
    }

    pub fn decode_frame(frame: &[u8]) -> Result<Self, DecodeError> {
        decode_codec_frame(frame, &decode_limits())
    }

    fn unsigned_payload(&self) -> Vec<u8> {
        let mut encoder = CborEncoder::new();
        self.encode_fields(&mut encoder, false);
        encoder.into_bytes()
    }

    fn encode_fields(&self, encoder: &mut CborEncoder, include_proof: bool) {
        encoder.write_map_header(if include_proof { 5 } else { 4 });
        write_key(encoder, 0);
        encoder.write_unsigned(u64::from(Self::MESSAGE_TYPE_ID));
        write_key(encoder, 1);
        encoder.write_unsigned(u64::from(self.protocol_schema_version));
        write_key(encoder, 2);
        encode_owned_launch_v2(encoder, &self.owned_launch);
        write_key(encoder, 3);
        encoder.write_bool(self.graceful);
        if include_proof {
            write_key(encoder, 4);
            encoder.write_byte_string(&self.proof);
        }
    }
}

impl fmt::Debug for ProtectedShutdownAckV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProtectedShutdownAckV2")
            .field("graceful", &self.graceful)
            .field("provider_binding", self.owned_launch.provider_binding())
            .field("protected_fields", &"<redacted>")
            .finish()
    }
}

impl DeterministicCodec for ProtectedShutdownAckV2 {
    const MESSAGE_TYPE_ID: u32 = 26;

    fn encode(&self, encoder: &mut CborEncoder) -> Result<(), EncodeError> {
        self.encode_fields(encoder, true);
        Ok(())
    }

    fn decode(type_id: u32, decoder: &mut CborDecoder<'_>) -> Result<Self, DecodeError> {
        if type_id != Self::MESSAGE_TYPE_ID || decoder.read_map_header(5)? != 5 {
            return Err(DecodeError::UnknownMessageType { type_id });
        }
        expect_key(decoder, 0)?;
        expect_message_type(decoder, Self::MESSAGE_TYPE_ID)?;
        expect_schema_version(decoder, PROTOCOL_SCHEMA_VERSION_V2)?;
        expect_key(decoder, 2)?;
        let owned_launch = decode_owned_launch_v2(decoder)?;
        expect_key(decoder, 3)?;
        let graceful = decoder.read_bool()?;
        expect_key(decoder, 4)?;
        let proof = decode_fixed::<32>(decoder)?;
        Ok(Self {
            protocol_schema_version: PROTOCOL_SCHEMA_VERSION_V2,
            owned_launch,
            graceful,
            proof,
        })
    }
}

fn encode_provider_binding(encoder: &mut CborEncoder, binding: &ProviderActivationBindingV1) {
    encoder.write_map_header(3);
    write_key(encoder, 1);
    encoder.write_unsigned(binding.mode.wire_code());
    write_key(encoder, 2);
    encoder.write_text_string(&binding.profile_id);
    write_key(encoder, 3);
    encoder.write_byte_string(&binding.profile_digest);
}

fn decode_provider_binding(
    decoder: &mut CborDecoder<'_>,
) -> Result<ProviderActivationBindingV1, DecodeError> {
    if decoder.read_map_header(3)? != 3 {
        return Err(DecodeError::UnknownField { key: 3 });
    }
    expect_key(decoder, 1)?;
    let mode = ProviderActivationModeV1::from_wire_code(decoder.read_unsigned(2)?)?;
    expect_key(decoder, 2)?;
    let profile_id = decoder.read_text_string(MAX_PROFILE_ID_BYTES)?.to_owned();
    expect_key(decoder, 3)?;
    let profile_digest = decode_fixed::<32>(decoder)?;
    ProviderActivationBindingV1::new(mode, profile_id, profile_digest)
        .map_err(|_| DecodeError::UnknownField { key: 3 })
}

fn encode_owned_launch_v2(encoder: &mut CborEncoder, owned: &ProtectedOwnedLaunchV2) {
    encoder.write_map_header(2);
    write_key(encoder, 1);
    encode_owned_launch(encoder, &owned.compatibility_owned_launch);
    write_key(encoder, 2);
    encode_provider_binding(encoder, &owned.provider_binding);
}

fn decode_owned_launch_v2(
    decoder: &mut CborDecoder<'_>,
) -> Result<ProtectedOwnedLaunchV2, DecodeError> {
    if decoder.read_map_header(2)? != 2 {
        return Err(DecodeError::UnknownField { key: 2 });
    }
    expect_key(decoder, 1)?;
    let compatibility_owned_launch = decode_owned_launch(decoder)?;
    expect_key(decoder, 2)?;
    let provider_binding = decode_provider_binding(decoder)?;
    ProtectedOwnedLaunchV2::new(compatibility_owned_launch, provider_binding)
        .map_err(|_| DecodeError::UnknownField { key: 2 })
}

fn derive_key(secret: &[u8; 32], role: &[u8]) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(secret).expect("HMAC accepts fixed keys");
    mac.update(KEY_DERIVATION_DOMAIN);
    mac.update(role);
    mac.finalize().into_bytes().into()
}

fn authenticated_mac(key: &[u8; 32], domain: &[u8], payload: &[u8]) -> [u8; 32] {
    authenticated_mac_version(key, domain, PROTOCOL_SCHEMA_VERSION, payload)
}

fn authenticated_mac_version(
    key: &[u8; 32],
    domain: &[u8],
    schema_version: u32,
    payload: &[u8],
) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts fixed keys");
    mac.update(domain);
    mac.update(&[0]);
    mac.update(&schema_version.to_be_bytes());
    mac.update(payload);
    mac.finalize().into_bytes().into()
}

fn valid_text(value: &str, max_bytes: usize) -> bool {
    !value.is_empty()
        && value.len() <= max_bytes
        && !value.chars().any(|character| character.is_control())
}

fn write_key(encoder: &mut CborEncoder, key: u64) {
    encoder.write_unsigned(key);
}

fn expect_key(decoder: &mut CborDecoder<'_>, expected: u64) -> Result<(), DecodeError> {
    let key = decoder.read_unsigned(expected.max(16))?;
    if key == expected {
        Ok(())
    } else {
        Err(DecodeError::UnknownField { key })
    }
}

fn expect_message_type(decoder: &mut CborDecoder<'_>, expected: u32) -> Result<(), DecodeError> {
    let actual = decoder.read_unsigned(u64::from(u32::MAX))?;
    if actual == u64::from(expected) {
        Ok(())
    } else {
        Err(DecodeError::UnknownMessageType {
            type_id: u32::try_from(actual).unwrap_or(u32::MAX),
        })
    }
}

fn expect_schema(decoder: &mut CborDecoder<'_>) -> Result<(), DecodeError> {
    expect_schema_version(decoder, PROTOCOL_SCHEMA_VERSION)
}

fn expect_schema_version(decoder: &mut CborDecoder<'_>, expected: u32) -> Result<(), DecodeError> {
    expect_key(decoder, 1)?;
    if decoder.read_unsigned(u64::from(u32::MAX))? == u64::from(expected) {
        Ok(())
    } else {
        Err(DecodeError::UnknownField { key: 1 })
    }
}

fn decode_fixed<const N: usize>(decoder: &mut CborDecoder<'_>) -> Result<[u8; N], DecodeError> {
    let bytes = decoder.read_byte_string(N)?;
    if bytes.len() != N {
        return Err(DecodeError::TruncatedCbor {
            offset: decoder.position(),
        });
    }
    let mut output = [0; N];
    output.copy_from_slice(bytes);
    Ok(output)
}

fn encode_executable(encoder: &mut CborEncoder, executable: &ExecutableIdentityV1) {
    encoder.write_map_header(3);
    write_key(encoder, 1);
    encoder.write_byte_string(&executable.executable_sha256);
    write_key(encoder, 2);
    encoder.write_byte_string(&executable.canonical_path_sha256);
    write_key(encoder, 3);
    encoder.write_unsigned(executable.byte_length);
}

fn decode_executable(decoder: &mut CborDecoder<'_>) -> Result<ExecutableIdentityV1, DecodeError> {
    if decoder.read_map_header(3)? != 3 {
        return Err(DecodeError::UnknownField { key: 9 });
    }
    expect_key(decoder, 1)?;
    let executable_sha256 = decode_fixed::<32>(decoder)?;
    expect_key(decoder, 2)?;
    let canonical_path_sha256 = decode_fixed::<32>(decoder)?;
    expect_key(decoder, 3)?;
    let byte_length = decoder.read_unsigned(u64::MAX)?;
    ExecutableIdentityV1::new(executable_sha256, canonical_path_sha256, byte_length)
        .map_err(|_| DecodeError::UnknownField { key: 3 })
}

fn encode_profile(encoder: &mut CborEncoder, profile: &ProtectedRuntimeProfileV1) {
    encoder.write_map_header(5);
    write_key(encoder, 1);
    encoder.write_text_string(&profile.transport_profile_id);
    write_key(encoder, 2);
    encoder.write_unsigned(u64::from(profile.runtime_profile_schema_version));
    write_key(encoder, 3);
    encoder.write_text_string(&profile.profile_id);
    write_key(encoder, 4);
    encoder.write_byte_string(&profile.profile_hash);
    write_key(encoder, 5);
    encoder.write_byte_string(&profile.capability_digest);
}

fn decode_profile(decoder: &mut CborDecoder<'_>) -> Result<ProtectedRuntimeProfileV1, DecodeError> {
    if decoder.read_map_header(5)? != 5 {
        return Err(DecodeError::UnknownField { key: 8 });
    }
    expect_key(decoder, 1)?;
    let transport_profile_id = decoder.read_text_string(MAX_PROFILE_ID_BYTES)?.to_owned();
    expect_key(decoder, 2)?;
    let schema = u32::try_from(decoder.read_unsigned(u64::from(u32::MAX))?)
        .map_err(|_| DecodeError::UnknownField { key: 2 })?;
    expect_key(decoder, 3)?;
    let profile_id = decoder.read_text_string(MAX_PROFILE_ID_BYTES)?.to_owned();
    expect_key(decoder, 4)?;
    let profile_hash = decode_fixed::<32>(decoder)?;
    expect_key(decoder, 5)?;
    let capability_digest = decode_fixed::<32>(decoder)?;
    ProtectedRuntimeProfileV1::new(
        transport_profile_id,
        schema,
        profile_id,
        profile_hash,
        capability_digest,
    )
    .map_err(|_| DecodeError::UnknownField { key: 5 })
}

fn encode_stable(encoder: &mut CborEncoder, stable: &StableRuntimeBindingV1) {
    encoder.write_map_header(6);
    write_key(encoder, 1);
    encoder.write_byte_string(&stable.authority_id);
    write_key(encoder, 2);
    encoder.write_text_string(&stable.principal_id);
    write_key(encoder, 3);
    encoder.write_byte_string(&stable.lineage_id);
    write_key(encoder, 4);
    encoder.write_text_string(&stable.profile_id);
    write_key(encoder, 5);
    encoder.write_byte_string(&stable.profile_hash);
    write_key(encoder, 6);
    encoder.write_byte_string(&stable.capability_digest);
}

fn decode_stable(decoder: &mut CborDecoder<'_>) -> Result<StableRuntimeBindingV1, DecodeError> {
    if decoder.read_map_header(6)? != 6 {
        return Err(DecodeError::UnknownField { key: 6 });
    }
    expect_key(decoder, 1)?;
    let authority_id = decode_fixed::<16>(decoder)?;
    expect_key(decoder, 2)?;
    let principal_id = decoder.read_text_string(MAX_PRINCIPAL_ID_BYTES)?.to_owned();
    expect_key(decoder, 3)?;
    let lineage_id = decode_fixed::<16>(decoder)?;
    expect_key(decoder, 4)?;
    let profile_id = decoder.read_text_string(MAX_PROFILE_ID_BYTES)?.to_owned();
    expect_key(decoder, 5)?;
    let profile_hash = decode_fixed::<32>(decoder)?;
    expect_key(decoder, 6)?;
    let capability_digest = decode_fixed::<32>(decoder)?;
    StableRuntimeBindingV1::new(
        authority_id,
        principal_id,
        lineage_id,
        profile_id,
        profile_hash,
        capability_digest,
    )
    .map_err(|_| DecodeError::UnknownField { key: 6 })
}

fn encode_owned_launch(encoder: &mut CborEncoder, owned: &ProtectedOwnedLaunchV1) {
    encoder.write_map_header(8);
    write_key(encoder, 1);
    encoder.write_byte_string(&owned.launch_authority_id);
    write_key(encoder, 2);
    encoder.write_byte_string(&owned.desktop_host_instance_id);
    write_key(encoder, 3);
    encode_executable(encoder, &owned.executable);
    write_key(encoder, 4);
    encode_profile(encoder, &owned.profile);
    write_key(encoder, 5);
    encode_stable(encoder, &owned.stable);
    write_key(encoder, 6);
    encoder.write_byte_string(&owned.daemon_instance_id);
    write_key(encoder, 7);
    encoder.write_unsigned(owned.launch_generation);
    write_key(encoder, 8);
    encoder.write_byte_string(&owned.session_id);
}

fn decode_owned_launch(
    decoder: &mut CborDecoder<'_>,
) -> Result<ProtectedOwnedLaunchV1, DecodeError> {
    if decoder.read_map_header(8)? != 8 {
        return Err(DecodeError::UnknownField { key: 2 });
    }
    expect_key(decoder, 1)?;
    let launch_authority_id = decode_fixed::<16>(decoder)?;
    expect_key(decoder, 2)?;
    let desktop_host_instance_id = decode_fixed::<16>(decoder)?;
    expect_key(decoder, 3)?;
    let executable = decode_executable(decoder)?;
    expect_key(decoder, 4)?;
    let profile = decode_profile(decoder)?;
    expect_key(decoder, 5)?;
    let stable = decode_stable(decoder)?;
    expect_key(decoder, 6)?;
    let daemon_instance_id = decode_fixed::<16>(decoder)?;
    expect_key(decoder, 7)?;
    let launch_generation = decoder.read_unsigned(u64::MAX)?;
    expect_key(decoder, 8)?;
    let session_id = decode_fixed::<16>(decoder)?;
    ProtectedOwnedLaunchV1::new(
        launch_authority_id,
        desktop_host_instance_id,
        executable,
        profile,
        stable,
        daemon_instance_id,
        launch_generation,
        session_id,
    )
    .map_err(|_| DecodeError::UnknownField { key: 8 })
}

fn encode_disposition(encoder: &mut CborEncoder, disposition: &ActivationDispositionV1) {
    match disposition {
        ActivationDispositionV1::FirstActivation => {
            encoder.write_map_header(1);
            write_key(encoder, 1);
            encoder.write_unsigned(1);
        }
        ActivationDispositionV1::Existing(stable) => {
            encoder.write_map_header(2);
            write_key(encoder, 1);
            encoder.write_unsigned(2);
            write_key(encoder, 2);
            encode_stable(encoder, stable);
        }
        ActivationDispositionV1::ResumeFirstActivation(pending) => {
            encoder.write_map_header(2);
            write_key(encoder, 1);
            encoder.write_unsigned(3);
            write_key(encoder, 2);
            encode_pending(encoder, pending);
        }
    }
}

fn decode_disposition(
    decoder: &mut CborDecoder<'_>,
) -> Result<ActivationDispositionV1, DecodeError> {
    let length = decoder.read_map_header(2)?;
    expect_key(decoder, 1)?;
    match decoder.read_unsigned(3)? {
        1 if length == 1 => Ok(ActivationDispositionV1::FirstActivation),
        2 if length == 2 => {
            expect_key(decoder, 2)?;
            Ok(ActivationDispositionV1::Existing(Box::new(decode_stable(
                decoder,
            )?)))
        }
        3 if length == 2 => {
            expect_key(decoder, 2)?;
            Ok(ActivationDispositionV1::ResumeFirstActivation(Box::new(
                decode_pending(decoder)?,
            )))
        }
        value => Err(DecodeError::UnknownField { key: value }),
    }
}

fn encode_pending(encoder: &mut CborEncoder, pending: &PendingFirstActivationV1) {
    encoder.write_map_header(5);
    write_key(encoder, 1);
    encoder.write_byte_string(&pending.preparation_id);
    write_key(encoder, 2);
    encoder.write_byte_string(&pending.runtime_root_identity);
    write_key(encoder, 3);
    encode_stable(encoder, &pending.stable);
    write_key(encoder, 4);
    encode_executable(encoder, &pending.executable);
    write_key(encoder, 5);
    encode_profile(encoder, &pending.profile);
}

fn decode_pending(decoder: &mut CborDecoder<'_>) -> Result<PendingFirstActivationV1, DecodeError> {
    if decoder.read_map_header(5)? != 5 {
        return Err(DecodeError::UnknownField { key: 2 });
    }
    expect_key(decoder, 1)?;
    let preparation_id = decode_fixed::<16>(decoder)?;
    expect_key(decoder, 2)?;
    let runtime_root_identity = decode_fixed::<32>(decoder)?;
    expect_key(decoder, 3)?;
    let stable = decode_stable(decoder)?;
    expect_key(decoder, 4)?;
    let executable = decode_executable(decoder)?;
    expect_key(decoder, 5)?;
    let profile = decode_profile(decoder)?;
    PendingFirstActivationV1::new(
        preparation_id,
        runtime_root_identity,
        stable,
        executable,
        profile,
    )
    .map_err(|_| DecodeError::UnknownField { key: 5 })
}

fn decode_limits() -> DecodeLimits {
    DecodeLimits {
        max_frame_bytes: MAX_FRAME_BYTES,
        max_recursion_depth: 16,
        max_array_items: MAX_CAPABILITIES as u32,
        max_map_items: 32,
        max_text_bytes: MAX_TEXT_BYTES,
        max_byte_string_bytes: MAX_CERTIFICATE_DER_BYTES,
        max_unsigned: u64::MAX,
        min_signed: i64::MIN,
        max_signed: i64::MAX,
        max_string_bytes: MAX_TEXT_BYTES,
        max_nesting_depth: 16,
    }
}

const _: usize = MAX_PAYLOAD_BYTES;
