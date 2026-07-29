//! Bootstrap handshake message types (Schema v1).
//!
//! Five message types exchanged during the protocol negotiation phase:
//! HostHello → PluginHello → (NegotiationRejected | ProfileSelected) → SelectionAcknowledged.

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

// CBOR message type IDs:
// 1 = HostHello, 2 = PluginHello, 3 = NegotiationRejected,
// 4 = ProfileSelected, 5 = SelectionAcknowledged

impl DeterministicCodec for BootstrapMessage {
    const MESSAGE_TYPE_ID: u32 = 0; // BootstrapMessage is a wrapper

    fn encode(&self, enc: &mut CborEncoder) -> Result<(), EncodeError> {
        match self {
            Self::HostHello(m) => {
                enc.write_map_header(4);
                // Key ordering (bytewise lexicographic): 1,2,3,4
                // Key 1: nonce
                enc.write_unsigned(1);
                enc.write_byte_string(m.nonce.as_bytes());
                // Key 2: host_identity
                enc.write_unsigned(2);
                encode_host_identity(enc, &m.host_identity);
                // Key 3: supported_profiles
                enc.write_unsigned(3);
                enc.write_array_header(m.supported_profiles.len() as u64);
                for prof in m.supported_profiles.as_slice() {
                    encode_profile_ref(enc, prof);
                }
                // Key 4: negotiation_snapshot
                enc.write_unsigned(4);
                enc.write_byte_string(m.negotiation_snapshot.as_bytes());
                Ok(())
            }
            Self::PluginHello(m) => {
                enc.write_map_header(11);
                // Keys sorted: 1,2,3,4,5,6,7,8,9,10,11
                enc.write_unsigned(1);
                enc.write_byte_string(m.host_nonce.as_bytes());
                enc.write_unsigned(2);
                enc.write_byte_string(m.plugin_nonce.as_bytes());
                enc.write_unsigned(3);
                encode_host_identity(enc, &m.host_identity);
                enc.write_unsigned(4);
                enc.write_text_string(m.package_id.as_str());
                enc.write_unsigned(5);
                encode_package_digest(enc, &m.package_digest);
                enc.write_unsigned(6);
                enc.write_text_string(m.package_version.as_str());
                enc.write_unsigned(7);
                enc.write_byte_string(m.manifest_digest.as_bytes());
                enc.write_unsigned(8);
                encode_host_identity(enc, &m.plugin_identity);
                enc.write_unsigned(9);
                enc.write_text_string(m.target_identity.as_str());
                enc.write_unsigned(10);
                enc.write_array_header(m.supported_profiles.len() as u64);
                for prof in m.supported_profiles.as_slice() {
                    encode_profile_ref(enc, prof);
                }
                // Key 11: entrypoint
                enc.write_unsigned(11);
                enc.write_text_string(m.entrypoint.as_str());
                Ok(())
            }
            Self::NegotiationRejected(m) => {
                enc.write_map_header(1);
                enc.write_unsigned(1);
                enc.write_unsigned(reject_reason_code(&m.reason));
                Ok(())
            }
            Self::ProfileSelected(m) => {
                enc.write_map_header(5);
                enc.write_unsigned(1);
                enc.write_byte_string(m.host_nonce.as_bytes());
                enc.write_unsigned(2);
                enc.write_byte_string(m.plugin_nonce.as_bytes());
                enc.write_unsigned(3);
                enc.write_byte_string(m.session_id.as_bytes());
                enc.write_unsigned(4);
                enc.write_text_string(m.profile_id.as_str());
                enc.write_unsigned(5);
                enc.write_byte_string(m.profile_digest.as_bytes());
                Ok(())
            }
            Self::SelectionAcknowledged(m) => {
                enc.write_map_header(5);
                enc.write_unsigned(1);
                enc.write_byte_string(m.host_nonce.as_bytes());
                enc.write_unsigned(2);
                enc.write_byte_string(m.plugin_nonce.as_bytes());
                enc.write_unsigned(3);
                enc.write_byte_string(m.session_id.as_bytes());
                enc.write_unsigned(4);
                enc.write_text_string(m.profile_id.as_str());
                enc.write_unsigned(5);
                enc.write_byte_string(m.profile_digest.as_bytes());
                Ok(())
            }
        }
    }

    fn decode(_type_id: u32, dec: &mut CborDecoder) -> Result<Self, DecodeError> {
        // Dispatch by canonical map length. Selection acknowledgement carries
        // a mandatory direction marker and therefore cannot reflect selection.
        let map_len = dec.read_map_header(64)?;
        match map_len {
            1 => decode_negotiation_rejected(dec),
            4 => decode_host_hello(dec),
            5 => decode_profile_selected(dec),
            11 => decode_plugin_hello(dec),
            _ => Err(DecodeError::UnknownMessageType {
                type_id: map_len as u32,
            }),
        }
    }
}

// ── Decode helpers ────────────────────────────────────────────────────────

fn decode_host_hello(dec: &mut CborDecoder) -> Result<BootstrapMessage, DecodeError> {
    let mut nonce = None;
    let mut host_identity = None;
    let mut supported_profiles = BoundedProfileRefVec::new();
    let mut negotiation_snapshot = None;

    let mut seen = [false; 5]; // keys 1-4
    for _ in 0..4 {
        let key = dec.read_unsigned(10)?;
        if key < 1 || key > 4 || seen[key as usize] {
            return Err(DecodeError::DuplicateMapKey { key });
        }
        seen[key as usize] = true;
        match key {
            1 => nonce = Some(decode_nonce(dec)?),
            2 => host_identity = Some(decode_host_identity(dec)?),
            3 => supported_profiles = decode_profile_ref_vec(dec)?,
            4 => negotiation_snapshot = Some(decode_negotiation_snapshot_digest(dec)?),
            _ => return Err(DecodeError::UnknownField { key }),
        }
    }

    Ok(BootstrapMessage::HostHello(HostHello {
        nonce: nonce.ok_or(DecodeError::MissingRequiredField { key: 1 })?,
        host_identity: host_identity.ok_or(DecodeError::MissingRequiredField { key: 2 })?,
        supported_profiles,
        negotiation_snapshot: negotiation_snapshot
            .ok_or(DecodeError::MissingRequiredField { key: 4 })?,
    }))
}

fn decode_plugin_hello(dec: &mut CborDecoder) -> Result<BootstrapMessage, DecodeError> {
    let mut host_nonce = None;
    let mut plugin_nonce = None;
    let mut host_identity = None;
    let mut package_id = None;
    let mut package_digest = None;
    let mut package_version = None;
    let mut manifest_digest = None;
    let mut plugin_identity = None;
    let mut target_identity = None;
    let mut supported_profiles = BoundedProfileRefVec::new();
    let mut entrypoint = None;

    let mut seen = [false; 12]; // keys 1-11
    for _ in 0..11 {
        let key = dec.read_unsigned(12)?;
        if key < 1 || key > 11 || seen[key as usize] {
            return Err(DecodeError::DuplicateMapKey { key });
        }
        seen[key as usize] = true;
        match key {
            1 => host_nonce = Some(decode_nonce(dec)?),
            2 => plugin_nonce = Some(decode_nonce(dec)?),
            3 => host_identity = Some(decode_host_identity(dec)?),
            4 => package_id = Some(decode_plugin_id(dec)?),
            5 => package_digest = Some(decode_package_digest(dec)?),
            6 => package_version = Some(decode_plugin_version(dec)?),
            7 => manifest_digest = Some(decode_manifest_digest(dec)?),
            8 => plugin_identity = Some(decode_host_identity(dec)?),
            9 => target_identity = Some(decode_target_identity(dec)?),
            10 => supported_profiles = decode_profile_ref_vec(dec)?,
            11 => entrypoint = Some(decode_entrypoint_identity(dec)?),
            _ => return Err(DecodeError::UnknownField { key }),
        }
    }

    Ok(BootstrapMessage::PluginHello(PluginHello {
        host_nonce: host_nonce.ok_or(DecodeError::MissingRequiredField { key: 1 })?,
        plugin_nonce: plugin_nonce.ok_or(DecodeError::MissingRequiredField { key: 2 })?,
        host_identity: host_identity.ok_or(DecodeError::MissingRequiredField { key: 3 })?,
        package_id: package_id.ok_or(DecodeError::MissingRequiredField { key: 4 })?,
        package_digest: package_digest.ok_or(DecodeError::MissingRequiredField { key: 5 })?,
        package_version: package_version.ok_or(DecodeError::MissingRequiredField { key: 6 })?,
        manifest_digest: manifest_digest.ok_or(DecodeError::MissingRequiredField { key: 7 })?,
        plugin_identity: plugin_identity.ok_or(DecodeError::MissingRequiredField { key: 8 })?,
        target_identity: target_identity.ok_or(DecodeError::MissingRequiredField { key: 9 })?,
        entrypoint: entrypoint.ok_or(DecodeError::MissingRequiredField { key: 11 })?,
        supported_profiles,
    }))
}

fn decode_negotiation_rejected(dec: &mut CborDecoder) -> Result<BootstrapMessage, DecodeError> {
    let key = dec.read_unsigned(10)?;
    if key != 1 {
        return Err(DecodeError::UnknownField { key });
    }
    let reason_code = dec.read_unsigned(10)?;
    let reason = reject_reason_from_code(reason_code)
        .ok_or(DecodeError::UnknownField { key: reason_code })?;
    Ok(BootstrapMessage::NegotiationRejected(NegotiationRejected {
        reason,
    }))
}

fn decode_profile_selected(dec: &mut CborDecoder) -> Result<BootstrapMessage, DecodeError> {
    let mut host_nonce = None;
    let mut plugin_nonce = None;
    let mut session_id = None;
    let mut profile_id = None;
    let mut profile_digest = None;

    let mut seen = [false; 6]; // keys 1-5
    for _ in 0..5 {
        let key = dec.read_unsigned(6)?;
        if key < 1 || key > 5 || seen[key as usize] {
            return Err(DecodeError::DuplicateMapKey { key });
        }
        seen[key as usize] = true;
        match key {
            1 => host_nonce = Some(decode_nonce(dec)?),
            2 => plugin_nonce = Some(decode_nonce(dec)?),
            3 => session_id = Some(decode_session_id(dec)?),
            4 => profile_id = Some(decode_profile_id(dec)?),
            5 => profile_digest = Some(decode_profile_digest(dec)?),
            _ => return Err(DecodeError::UnknownField { key }),
        }
    }

    Ok(BootstrapMessage::ProfileSelected(ProfileSelected {
        host_nonce: host_nonce.ok_or(DecodeError::MissingRequiredField { key: 1 })?,
        plugin_nonce: plugin_nonce.ok_or(DecodeError::MissingRequiredField { key: 2 })?,
        session_id: session_id.ok_or(DecodeError::MissingRequiredField { key: 3 })?,
        profile_id: profile_id.ok_or(DecodeError::MissingRequiredField { key: 4 })?,
        profile_digest: profile_digest.ok_or(DecodeError::MissingRequiredField { key: 5 })?,
    }))
}

// ── Field-level decoders ──────────────────────────────────────────────────

fn decode_nonce(dec: &mut CborDecoder) -> Result<Nonce, DecodeError> {
    let bytes = dec.read_byte_string(16)?;
    if bytes.len() != 16 {
        return Err(DecodeError::TruncatedCbor { offset: 0 });
    }
    let mut arr = [0u8; 16];
    arr.copy_from_slice(bytes);
    Ok(Nonce::from_bytes(arr))
}

fn decode_session_id(dec: &mut CborDecoder) -> Result<ProtocolSessionId, DecodeError> {
    let bytes = dec.read_byte_string(16)?;
    if bytes.len() != 16 {
        return Err(DecodeError::TruncatedCbor { offset: 0 });
    }
    let mut arr = [0u8; 16];
    arr.copy_from_slice(bytes);
    // Check UUID version/variant
    if arr[6] >> 4 != 7 {
        return Err(DecodeError::InvalidUuidVariant { offset: 0 });
    }
    if arr[8] >> 6 != 0b10 {
        return Err(DecodeError::InvalidUuidVariant { offset: 0 });
    }
    Ok(ProtocolSessionId::from_bytes(arr))
}

fn decode_profile_id(dec: &mut CborDecoder) -> Result<ProfileId, DecodeError> {
    let s = dec.read_text_string(256)?;
    ProfileId::new(s).map_err(|_| DecodeError::InvalidUtf8 { offset: 0 })
}

fn decode_profile_digest(dec: &mut CborDecoder) -> Result<ProfileDigest, DecodeError> {
    let bytes = dec.read_byte_string(32)?;
    if bytes.len() != 32 {
        return Err(DecodeError::TruncatedCbor { offset: 0 });
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(bytes);
    Ok(ProfileDigest::from_bytes(arr))
}

fn decode_plugin_id(dec: &mut CborDecoder) -> Result<PluginId, DecodeError> {
    let s = dec.read_text_string(256)?;
    PluginId::new(s).map_err(|_| DecodeError::InvalidUtf8 { offset: 0 })
}

fn decode_plugin_version(dec: &mut CborDecoder) -> Result<PluginVersion, DecodeError> {
    let s = dec.read_text_string(256)?;
    PluginVersion::new(s).map_err(|_| DecodeError::InvalidUtf8 { offset: 0 })
}

fn decode_target_identity(dec: &mut CborDecoder) -> Result<TargetIdentity, DecodeError> {
    let s = dec.read_text_string(256)?;
    TargetIdentity::new(s).map_err(|_| DecodeError::InvalidUtf8 { offset: 0 })
}

fn decode_entrypoint_identity(dec: &mut CborDecoder) -> Result<EntrypointIdentity, DecodeError> {
    let s = dec.read_text_string(512)?;
    EntrypointIdentity::new(s).map_err(|_| DecodeError::InvalidUtf8 { offset: 0 })
}

fn decode_negotiation_snapshot_digest(
    dec: &mut CborDecoder,
) -> Result<ProtocolNegotiationSnapshotDigest, DecodeError> {
    let bytes = dec.read_byte_string(32)?;
    if bytes.len() != 32 {
        return Err(DecodeError::TruncatedCbor { offset: 0 });
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(bytes);
    Ok(ProtocolNegotiationSnapshotDigest::from_bytes(arr))
}

fn decode_manifest_digest(dec: &mut CborDecoder) -> Result<ManifestDigest, DecodeError> {
    let bytes = dec.read_byte_string(32)?;
    if bytes.len() != 32 {
        return Err(DecodeError::TruncatedCbor { offset: 0 });
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(bytes);
    Ok(ManifestDigest::from_bytes(arr))
}

fn decode_package_digest(dec: &mut CborDecoder) -> Result<PackageDigest, DecodeError> {
    let _map_len = dec.read_map_header(4)?;
    let mut algorithm = None;
    let mut digest_bytes = None;
    let mut seen_algo = false;
    for _ in 0..2 {
        let key = dec.read_unsigned(4)?;
        match key {
            1 => {
                if seen_algo {
                    return Err(DecodeError::DuplicateMapKey { key: 1 });
                }
                seen_algo = true;
                let code = dec.read_unsigned(10)?;
                algorithm = match code {
                    1 => Some(DigestAlgorithm::Sha256),
                    _ => return Err(DecodeError::UnknownField { key: code }),
                };
            }
            2 => {
                if digest_bytes.is_some() {
                    return Err(DecodeError::DuplicateMapKey { key: 2 });
                }
                let bytes = dec.read_byte_string(32)?;
                if bytes.len() != 32 {
                    return Err(DecodeError::TruncatedCbor { offset: 0 });
                }
                let mut arr = [0u8; 32];
                arr.copy_from_slice(bytes);
                digest_bytes = Some(arr);
            }
            _ => return Err(DecodeError::UnknownField { key }),
        }
    }
    Ok(PackageDigest::new(
        algorithm.ok_or(DecodeError::MissingRequiredField { key: 1 })?,
        digest_bytes.ok_or(DecodeError::MissingRequiredField { key: 2 })?,
    ))
}

fn decode_profile_ref_vec(dec: &mut CborDecoder) -> Result<BoundedProfileRefVec, DecodeError> {
    let array_len = dec.read_array_header(64)?;
    // Not truly bounded at decode — BoundedProfileRefVec is just a vec wrapper
    // for bootstrap. A proper limit should be enforced, but for now it's
    // bounded at construction time by the encode-side contract.
    let mut entries = Vec::new();
    for _ in 0..array_len {
        let _map_len = dec.read_map_header(4)?;
        let mut profile_id = None;
        let mut profile_digest = None;
        for _ in 0..2 {
            let key = dec.read_unsigned(3)?;
            match key {
                1 => {
                    if profile_id.is_some() {
                        return Err(DecodeError::DuplicateMapKey { key: 1 });
                    }
                    profile_id = Some(decode_profile_id(dec)?);
                }
                2 => {
                    if profile_digest.is_some() {
                        return Err(DecodeError::DuplicateMapKey { key: 2 });
                    }
                    profile_digest = Some(decode_profile_digest(dec)?);
                }
                _ => return Err(DecodeError::UnknownField { key }),
            }
        }
        let id = profile_id.ok_or(DecodeError::MissingRequiredField { key: 1 })?;
        let digest = profile_digest.ok_or(DecodeError::MissingRequiredField { key: 2 })?;
        entries.push(ProtocolProfileRef::new(id, digest));
    }
    Ok(BoundedProfileRefVec::from_vec(entries))
}

// ── Encode helpers ────────────────────────────────────────────────────────

fn encode_host_identity(enc: &mut CborEncoder, id: &HostExecutionIdentity) {
    match id {
        HostExecutionIdentity::Plugin(pi) => {
            enc.write_map_header(1);
            enc.write_unsigned(1);
            enc.write_text_string(pi.as_str());
        }
        HostExecutionIdentity::Migration(mi) => {
            enc.write_map_header(1);
            enc.write_unsigned(2);
            enc.write_text_string(mi.as_str());
        }
    }
}

fn decode_host_identity(dec: &mut CborDecoder) -> Result<HostExecutionIdentity, DecodeError> {
    let map_len = dec.read_map_header(2)?;
    let mut id = None;
    for _ in 0..map_len {
        let key = dec.read_unsigned(2)?;
        match key {
            1 => {
                let s = dec.read_text_string(256)?;
                id = Some(HostExecutionIdentity::Plugin(
                    PluginIdentity::new(s).map_err(|_| DecodeError::InvalidUtf8 { offset: 0 })?,
                ));
            }
            2 => {
                let s = dec.read_text_string(256)?;
                id = Some(HostExecutionIdentity::Migration(
                    MigrationIdentity::new(s)
                        .map_err(|_| DecodeError::InvalidUtf8 { offset: 0 })?,
                ));
            }
            _ => return Err(DecodeError::UnknownField { key }),
        }
    }
    id.ok_or(DecodeError::MissingRequiredField { key: 1 })
}

fn encode_profile_ref(enc: &mut CborEncoder, prof: &crate::profile::ProtocolProfileRef) {
    enc.write_map_header(2);
    enc.write_unsigned(1);
    enc.write_text_string(prof.profile_id().as_str());
    enc.write_unsigned(2);
    enc.write_byte_string(prof.profile_digest().as_bytes());
}

fn encode_package_digest(enc: &mut CborEncoder, pd: &PackageDigest) {
    enc.write_map_header(2);
    enc.write_unsigned(1);
    enc.write_unsigned(match pd.algorithm() {
        DigestAlgorithm::Sha256 => 1,
    });
    enc.write_unsigned(2);
    enc.write_byte_string(pd.as_bytes());
}

fn reject_reason_code(r: &NegotiationRejectReason) -> u64 {
    match r {
        NegotiationRejectReason::ProfileNotSupported => 1,
        NegotiationRejectReason::DigestMismatch => 2,
        NegotiationRejectReason::IdentityRejected => 3,
        NegotiationRejectReason::VersionIncompatible => 4,
    }
}

fn reject_reason_from_code(code: u64) -> Option<NegotiationRejectReason> {
    match code {
        1 => Some(NegotiationRejectReason::ProfileNotSupported),
        2 => Some(NegotiationRejectReason::DigestMismatch),
        3 => Some(NegotiationRejectReason::IdentityRejected),
        4 => Some(NegotiationRejectReason::VersionIncompatible),
        _ => None,
    }
}
