use std::fmt;
use std::sync::Arc;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use reqwest::header::{ACCEPT, AUTHORIZATION, CONTENT_TYPE, HeaderValue};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use zeroize::{Zeroize, Zeroizing};

const MAXIMUM_CANONICAL_RESPONSE_BYTES: usize = 8 * 1024 * 1024;
const MAXIMUM_ERROR_RESPONSE_BYTES: usize = 8 * 1024;
const MAXIMUM_IDEMPOTENCY_KEY_BYTES: usize = 256;
const MAXIMUM_MESSAGE_TEXT_BYTES: usize = 64 * 1024;
/// Exact external/deterministic runtime capabilities. Ordering is canonical.
pub const REQUIRED_RUNTIME_CAPABILITIES: &[&str] = &[
    "conversation.create.v1",
    "conversation.generate_text.v1",
    "conversation.list_messages.v1",
    "replay.aggregate.open.v1",
    "replay.aggregate.retention_baseline.v1",
    "replay.aggregate.retention_baseline_resume.v2",
    "replay.aggregate.read_page.v1",
    "replay.aggregate.acknowledge.v1",
    "replay.aggregate.complete_catch_up.v1",
    "replay.aggregate.continue_live.v1",
    "replay.aggregate.sse.v1",
    "runtime.operational-telemetry.v1",
    "project.list.v1",
    "project.get.v1",
    "project.create.v1",
    "project.archive.v1",
    "project.restore.v1",
    "project.delete.v1",
    "workspace.list.v1",
    "workspace.get.v1",
    "workspace.create.v1",
    "workspace.open.v1",
];

/// Exact protected-desktop extension, enabled only with native root authority.
pub const PROTECTED_RUNTIME_CAPABILITIES: &[&str] = &[
    "conversation.create.v1",
    "conversation.generate_text.v1",
    "conversation.list_messages.v1",
    "replay.aggregate.open.v1",
    "replay.aggregate.retention_baseline.v1",
    "replay.aggregate.retention_baseline_resume.v2",
    "replay.aggregate.read_page.v1",
    "replay.aggregate.acknowledge.v1",
    "replay.aggregate.complete_catch_up.v1",
    "replay.aggregate.continue_live.v1",
    "replay.aggregate.sse.v1",
    "runtime.operational-telemetry.v1",
    "project.list.v1",
    "project.get.v1",
    "project.create.v1",
    "project.archive.v1",
    "project.restore.v1",
    "project.delete.v1",
    "workspace.list.v1",
    "workspace.get.v1",
    "workspace.create.v1",
    "workspace.open.v1",
    "workspace.bind_root.v3",
];

pub fn is_supported_capability_profile(values: &[String]) -> bool {
    [
        REQUIRED_RUNTIME_CAPABILITIES,
        PROTECTED_RUNTIME_CAPABILITIES,
    ]
    .iter()
    .any(|expected| {
        values
            .iter()
            .map(String::as_str)
            .eq(expected.iter().copied())
    })
}

/// Verifies every protected-bundled profile field used by the native root
/// authority boundary. External clients never satisfy this predicate.
#[must_use]
pub fn protected_profile_matches(client: &AuthenticatedRuntimeClient) -> bool {
    let session = client.session_info();
    client.transport_kind() == RuntimeTransportKind::ProtectedBundled
        && session.profile_id == crate::EXPECTED_BUNDLE_ID
        && session.schema_hash == crate::GOLDEN_BUNDLE_HASH
        && session
            .capabilities
            .iter()
            .map(String::as_str)
            .eq(PROTECTED_RUNTIME_CAPABILITIES.iter().copied())
        && capability_digest_hex(&session.capabilities)
            .is_some_and(|digest| digest == session.capability_digest)
        && nonempty_identity(session)
}

fn capability_digest_hex(capabilities: &[String]) -> Option<String> {
    use sha2::Digest;
    if capabilities
        .iter()
        .any(|value| value.len() > u32::MAX as usize)
    {
        return None;
    }
    let mut digest = sha2::Sha256::new();
    digest.update(b"gocode/local-runtime/capability-digest/v1\0");
    digest.update(u32::try_from(capabilities.len()).ok()?.to_be_bytes());
    for value in capabilities {
        digest.update(u32::try_from(value.len()).ok()?.to_be_bytes());
        digest.update(value.as_bytes());
    }
    Some(hex::encode(digest.finalize()))
}

fn nonempty_identity(session: &RuntimeSessionInfo) -> bool {
    [
        &session.authority_id,
        &session.principal_id,
        &session.event_log_lineage_id,
        &session.daemon_instance_id,
        &session.session_id,
        &session.certificate_sha256,
    ]
    .into_iter()
    .all(|value| !value.is_empty())
        && session.launch_generation != 0
        && session.authorization_epoch != 0
}

/// Strict `UUIDv7` identity used by the canonical client contract.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct CanonicalId(uuid::Uuid);

impl CanonicalId {
    /// Parses an RFC 9562 `UUIDv7` identity.
    ///
    /// # Errors
    ///
    /// Returns `InvalidRequest` for malformed, non-v7, or non-RFC identities.
    pub fn parse(value: &str) -> Result<Self, RuntimeApiError> {
        let parsed = uuid::Uuid::parse_str(value)
            .map_err(|_| RuntimeApiError::new(RuntimeApiErrorKind::InvalidRequest))?;
        if parsed.get_version_num() != 7 || parsed.get_variant() != uuid::Variant::RFC4122 {
            return Err(RuntimeApiError::new(RuntimeApiErrorKind::InvalidRequest));
        }
        Ok(Self(parsed))
    }

    /// Generates a fresh `UUIDv7` identity.
    #[must_use]
    pub fn now_v7() -> Self {
        Self(uuid::Uuid::now_v7())
    }
}

impl fmt::Display for CanonicalId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

impl Serialize for CanonicalId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for CanonicalId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::parse(&value).map_err(serde::de::Error::custom)
    }
}

/// Command identity and opaque idempotency key.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommandIdentity {
    command_id: CanonicalId,
    idempotency_key: String,
}

impl CommandIdentity {
    /// Validates one command identity for use as HTTP headers.
    ///
    /// # Errors
    ///
    /// Returns `InvalidRequest` for an empty, oversized, control-bearing, or
    /// non-header-safe idempotency key.
    pub fn new(
        command_id: CanonicalId,
        idempotency_key: impl Into<String>,
    ) -> Result<Self, RuntimeApiError> {
        let idempotency_key = idempotency_key.into();
        if idempotency_key.is_empty()
            || idempotency_key.len() > MAXIMUM_IDEMPOTENCY_KEY_BYTES
            || idempotency_key
                .as_bytes()
                .iter()
                .any(|byte| *byte < 0x20 || *byte == 0x7f)
            || HeaderValue::from_str(&idempotency_key).is_err()
        {
            return Err(RuntimeApiError::new(RuntimeApiErrorKind::InvalidRequest));
        }
        Ok(Self {
            command_id,
            idempotency_key,
        })
    }
}

/// Host-owned 32-byte daemon session authority.
///
/// The type intentionally implements neither `Debug`, `Display`, nor
/// serialization. The bytes are zeroized after the final clone is dropped.
#[derive(Clone)]
pub struct RuntimeSessionAuthority {
    bytes: Arc<Zeroizing<[u8; 32]>>,
    replay_binding: Option<gocode_api::RuntimeSessionBinding>,
}

impl RuntimeSessionAuthority {
    pub(crate) fn from_local_session(bytes: [u8; 32]) -> Self {
        Self {
            bytes: Arc::new(Zeroizing::new(bytes)),
            replay_binding: None,
        }
    }

    pub(crate) fn bind_replay_session(
        mut self,
        binding: Option<gocode_api::RuntimeSessionBinding>,
    ) -> Self {
        self.replay_binding = binding;
        self
    }

    pub(crate) const fn replay_binding(&self) -> Option<&gocode_api::RuntimeSessionBinding> {
        self.replay_binding.as_ref()
    }

    pub(crate) fn authorization_header(&self) -> Result<HeaderValue, RuntimeApiError> {
        let mut wire = String::from("GocodeSession ");
        wire.push_str(&URL_SAFE_NO_PAD.encode(self.bytes.as_ref().as_ref()));
        let mut header = HeaderValue::from_str(&wire)
            .map_err(|_| RuntimeApiError::new(RuntimeApiErrorKind::InvalidRequest))?;
        header.set_sensitive(true);
        wire.zeroize();
        Ok(header)
    }

    /// Copies the authority only for test-support forbidden-sink audits.
    #[cfg(feature = "test-support")]
    #[doc(hidden)]
    #[must_use]
    pub fn test_material(&self) -> Zeroizing<[u8; 32]> {
        Zeroizing::new(**self.bytes)
    }
}

pub type RuntimeCredential = RuntimeSessionAuthority;

/// Result of the exact authenticated runtime profile handshake.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RuntimeSessionInfo {
    /// Exact selected profile.
    pub profile_id: String,
    /// Exact canonical bundle digest.
    pub schema_hash: String,
    /// Safe runtime build version.
    pub runtime_version: String,
    /// Exact canonical capability set accepted for this session.
    pub capabilities: Vec<String>,
    /// Stable runtime authority UUID.
    pub authority_id: String,
    /// Authenticated local principal.
    pub principal_id: String,
    /// Stable Event Log lineage UUID.
    pub event_log_lineage_id: String,
    /// Fresh daemon launch UUID.
    pub daemon_instance_id: String,
    /// Durable positive daemon launch generation.
    pub launch_generation: u64,
    /// Ephemeral session UUID.
    pub session_id: String,
    /// Authorization epoch at session issuance.
    pub authorization_epoch: u64,
    /// Maximum sensitivity permitted for this session.
    pub sensitivity_ceiling: String,
    /// Exact pinned certificate digest.
    pub certificate_sha256: String,
    /// Digest of the exact ordered capability set.
    pub capability_digest: String,
}
