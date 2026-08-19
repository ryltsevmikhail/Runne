use crate::cbor::{CborDecoder, CborEncoder, DecodeError, DeterministicCodec, EncodeError};
use crate::digest::DigestAlgorithm;
use crate::digest::{
    ManifestDigest, PackageDigest, ProfileDigest, ProtocolNegotiationSnapshotDigest,
};
use crate::id::{
    EntrypointIdentity, MigrationIdentity, Nonce, PluginId, PluginIdentity, PluginVersion,
    ProfileId, ProtocolSessionId, TargetIdentity,
};
use crate::profile::BoundedProfileRefVec;
use crate::profile::ProtocolProfileRef;

// ── HostExecutionIdentity ─────────────────────────────────────────────────

/// Identifies what kind of host is executing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HostExecutionIdentity {
    /// A plugin runtime.
    Plugin(PluginIdentity),
    /// A migration runtime.
    Migration(MigrationIdentity),
}

// ── NegotiationRejectReason ───────────────────────────────────────────────

/// Reason for rejecting a protocol negotiation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NegotiationRejectReason {
    /// No compatible profile found.
    ProfileNotSupported,
    /// A digest did not match.
    DigestMismatch,
    /// The host/plugin identity was rejected.
    IdentityRejected,
    /// Protocol versions are incompatible.
    VersionIncompatible,
}

// ── Bootstrap message structs ─────────────────────────────────────────────

/// Host initiates negotiation with its capabilities.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostHello {
    /// Nonce for replay protection.
    pub nonce: Nonce,
    /// Identity of the host runtime.
    pub host_identity: HostExecutionIdentity,
    /// Profiles supported by the host.
    pub supported_profiles: BoundedProfileRefVec,
    /// Digest of the negotiation snapshot state.
    pub negotiation_snapshot: ProtocolNegotiationSnapshotDigest,
}

/// Plugin responds with its identity and capabilities.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PluginHello {
    /// Host nonce from HostHello.
    pub host_nonce: Nonce,
    /// Plugin-generated nonce for this handshake.
    pub plugin_nonce: Nonce,
    /// Identity of the host runtime.
    pub host_identity: HostExecutionIdentity,
    /// Plugin package identifier.
    pub package_id: PluginId,
    /// Content-addressed digest of the plugin package.
    pub package_digest: PackageDigest,
    /// Plugin version string (semver).
    pub package_version: PluginVersion,
    /// Digest of the plugin manifest.
    pub manifest_digest: ManifestDigest,
    /// Identity of the plugin runtime.
    pub plugin_identity: HostExecutionIdentity,
    /// Target execution identity.
    pub target_identity: TargetIdentity,
    /// Entrypoint within the plugin.
    pub entrypoint: EntrypointIdentity,
    /// Profiles supported by the plugin.
    pub supported_profiles: BoundedProfileRefVec,
}

/// Negotiation was rejected.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NegotiationRejected {
    /// Reason for the rejection.
    pub reason: NegotiationRejectReason,
}

/// Host selects a specific profile.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProfileSelected {
    /// Host nonce from HostHello.
    pub host_nonce: Nonce,
    /// Plugin nonce from PluginHello.
    pub plugin_nonce: Nonce,
    /// Established session identifier.
    pub session_id: ProtocolSessionId,
    /// Selected profile identifier.
    pub profile_id: ProfileId,
    /// Digest of the selected profile.
    pub profile_digest: ProfileDigest,
}

/// Plugin acknowledges profile selection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SelectionAcknowledged {
    /// Host nonce from HostHello.
    pub host_nonce: Nonce,
    /// Plugin nonce from PluginHello.
    pub plugin_nonce: Nonce,
    /// Established session identifier.
    pub session_id: ProtocolSessionId,
    /// Acknowledged profile identifier.
    pub profile_id: ProfileId,
    /// Digest of the acknowledged profile.
    pub profile_digest: ProfileDigest,
}

// ── BootstrapMessage enum ─────────────────────────────────────────────────

/// Closed enum of all bootstrap handshake messages.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BootstrapMessage {
    HostHello(HostHello),
    PluginHello(PluginHello),
    NegotiationRejected(NegotiationRejected),
    ProfileSelected(ProfileSelected),
    SelectionAcknowledged(SelectionAcknowledged),
}

// ── DeterministicCodec for BootstrapMessage ───────────────────────────────
