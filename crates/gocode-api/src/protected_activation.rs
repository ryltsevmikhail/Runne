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
const EXTERNAL_TRANSPORT_PROFILE_ID: &str = "gocode-local-runtime/2";
const KEY_DERIVATION_DOMAIN: &[u8] = b"gocode/bundled-launch/key-derivation/v1\0";
const BOOTSTRAP_DOMAIN: &[u8] = b"gocode/bundled-launch/bootstrap/v1";
const READINESS_DOMAIN: &[u8] = b"gocode/bundled-launch/readiness/v1";
const RENEW_DOMAIN: &[u8] = b"gocode/bundled-launch/renew/v1";
const SHUTDOWN_DOMAIN: &[u8] = b"gocode/bundled-launch/shutdown/v1";
const FIRST_ACTIVATION_PREPARE_DOMAIN: &[u8] = b"gocode/bundled-launch/first-activation-prepare/v1";
const FIRST_ACTIVATION_COMMIT_DOMAIN: &[u8] = b"gocode/bundled-launch/first-activation-commit/v1";

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
            Self::InvalidContract => "invalid_contract",
        })
    }
}

impl std::error::Error for LaunchAuthorityError {}

include!("protected_activation/secret.rs");
include!("protected_activation/identity.rs");
include!("protected_activation/binding.rs");
include!("protected_activation/request.rs");
include!("protected_activation/first_activation_prepared.rs");
include!("protected_activation/first_activation_commit.rs");
include!("protected_activation/owned_launch.rs");
include!("protected_activation/renew_request.rs");
include!("protected_activation/renew_ticket.rs");
include!("protected_activation/shutdown.rs");
include!("protected_activation/ready_model.rs");
include!("protected_activation/ready_codec.rs");
include!("protected_activation/wire_core.rs");
include!("protected_activation/wire_identity.rs");
include!("protected_activation/wire_binding.rs");
include!("protected_activation/wire_disposition.rs");
