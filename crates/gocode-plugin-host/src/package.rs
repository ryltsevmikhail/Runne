use core::fmt;
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::{Arc, Mutex},
};

use sha2::{Digest, Sha256};

use crate::{
    PluginActiveFence, PluginClass, PluginDigest, PluginGeneration, PluginGenerationPort,
    PluginGenerationPortError, PluginGenerationReadLease, PluginHookDispatchAuthorityPort,
    PluginHookDispatchClaim, PluginHookDispatchClaimResult, PluginHookDispatchError,
    PluginHookDispatchJournal, PluginHookDispatchJournalError, PluginHookDispatchJournalKey,
    PluginHookDispatchJournalResult, PluginHookDisposition, PluginHookRecoveredDispatch,
    PluginTrust,
};
use gocode_plugin_protocol::bootstrap::HostExecutionIdentity;
use gocode_plugin_protocol::cbor::CborEncoder;
use gocode_plugin_protocol::digest::{
    BootstrapSchemaDigest, BoundsProfileDigest, ManifestDigest, ProtocolNegotiationSnapshotDigest,
    SchemaBundleDigest, Sha256Digest, Sha256Provider, WireContractDigest,
};
use gocode_plugin_protocol::id::{
    EntrypointIdentity, PluginId, PluginIdentity, PluginVersion, ProtocolVersion, TargetIdentity,
};
use gocode_plugin_protocol::profile::{
    BoundedProfileRefVec, ProtocolProfileRef, ProtocolSupportProfile,
};

const PACKAGE_DIGEST_DOMAIN: &[u8] = b"GOCODE_PLUGIN_PACKAGE_V1\0";
const MANIFEST_DIGEST_DOMAIN: &[u8] = b"GOCODE_PLUGIN_MANIFEST_V1\0";
const FILE_DIGEST_DOMAIN: &[u8] = b"GOCODE_PLUGIN_FILE_BLOB_V1\0";
const FILE_TABLE_DIGEST_DOMAIN: &[u8] = b"GOCODE_PLUGIN_FILE_TABLE_V1\0";
const MANIFEST_CONTRACT_DIGEST: [u8; 32] = [0x15; 32];
const TRUST_BINDING_DIGEST_DOMAIN: &[u8] = b"GOCODE_PLUGIN_TRUST_BINDING_V1\0";
const NEGOTIATION_SNAPSHOT_DIGEST_DOMAIN: &[u8] = b"GOCODE_PLUGIN_NEGOTIATION_SNAPSHOT_V1\0";
const BUILTIN_PACKAGE_BYTES: &[u8] = b"gocode-plugin-host/builtin-package-v1";
const BUILTIN_MANIFEST_BYTES: &[u8] = b"GOCODE_PLUGIN_MANIFEST_V1\npackage_id=builtin\npackage_version=1.0.0\nhost_identity=host\nplugin_identity=plugin\ntarget_identity=target\nentrypoint=entrypoint\nfile_table_digest=sha256:7c095321ed00395bc7d98a7256f7493884c68727c9390ca67d6fa0fd5e7d0ef8\nprotocol_profile=builtin-profile-v2|sha256:6dbddbd754f8bff3d62cfefd31095bce32563ac2627705c924261c0bfe4f6c5d\nfile=entrypoint|executable|40|sha256:b819bdc75d5ae1d0f9f0611f08f58802c88cbbd015bef7aff3a0c3160e832834\nfile=package|data|37|sha256:c48131eae8e78a0f2fccc5d0bae39d73e44a8a1eb74484b1cc500e43de7e8253\n";
const BUILTIN_ENTRYPOINT_BYTES: &[u8] = b"gocode-plugin-host/builtin-entrypoint-v1";
const BUILTIN_PROTOCOL_PROFILE_BYTES: &[u8] = b"GOCODE_PLUGIN_PROFILE_V1\nprofile_id=builtin-profile-v2\nversion=1.0\nbootstrap_schema_digest=sha256:1111111111111111111111111111111111111111111111111111111111111111\nwire_contract_digest=sha256:2222222222222222222222222222222222222222222222222222222222222222\nsession_schema_bundle_digest=sha256:3333333333333333333333333333333333333333333333333333333333333333\nfeatures=bootstrap-v2\nbounds_profile_digest=sha256:4444444444444444444444444444444444444444444444444444444444444444\n";
const BUILTIN_TRUST_BINDING_BYTES: &[u8] = b"gocode-plugin-host/builtin-trust-binding-v1";

struct HostSha256;

impl Sha256Provider for HostSha256 {
    fn sha256(&self, data: &[u8]) -> Sha256Digest {
        Sha256Digest::from_bytes(Sha256::digest(data).into())
    }
}

fn protocol_profile_digest(
    profile: &ProtocolSupportProfile,
) -> gocode_plugin_protocol::digest::ProfileDigest {
    profile.profile_digest(&HostSha256)
}
/// Trusted ADR-0015 capture bounds, checked before retained ownership.
pub const MAX_MANIFEST_BYTES: usize = 1024 * 1024;
/// Maximum bytes for one profile or trust-binding artifact.
pub const MAX_PROFILE_OR_TRUST_BYTES: usize = 64 * 1024;
/// Maximum declared logical files in one captured package.
pub const MAX_PACKAGE_FILES: usize = 4096;
/// Maximum bytes retained for any one logical file.
pub const MAX_PACKAGE_FILE_BYTES: usize = 64 * 1024 * 1024;
/// Maximum total decoded bytes retained for a package capture.
pub const MAX_PACKAGE_RETAINED_BYTES: usize = 512 * 1024 * 1024;
/// Maximum slash-separated portable path segments.
pub const MAX_PACKAGE_PATH_DEPTH: usize = 32;
/// Maximum bytes in a portable package path before any segment processing.
pub const MAX_PACKAGE_PATH_BYTES: usize = MAX_PACKAGE_PATH_DEPTH * 129 - 1;

/// Registry-owned authority for one exact plugin package activation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PluginPackageAuthority {
    package_digest: PluginDigest,
    manifest_digest: PluginDigest,
    entrypoint_digest: PluginDigest,
    effective_class: PluginClass,
    effective_trust: PluginTrust,
    protocol_profile_digest: PluginDigest,
    trust_binding_digest: PluginDigest,
    activation: PluginActivationAuthority,
}

/// Immutable activation values issued only by the trusted registry loader.
#[derive(Debug, Clone, PartialEq, Eq)]
struct PluginActivationAuthority {
    profile: ProtocolProfileRef,
    advertised_profiles: BoundedProfileRefVec,
    negotiation_snapshot: ProtocolNegotiationSnapshotDigest,
    generation: PluginGeneration,
    metadata: PluginHelloMetadata,
}

impl PluginPackageAuthority {
    fn issue(
        source: &PluginPackageSource,
        effective_class: PluginClass,
        effective_trust: PluginTrust,
    ) -> Result<Self, TrustedRegistryLoadError> {
        // Every public handshake field is decoded from immutable captured bytes;
        // registry policy supplies only the non-public class and trust decision.
        let manifest = parse_manifest(&source.content.manifest_bytes)?;
        let support_profile = &source.content.protocol_profile;
        let profile = ProtocolProfileRef::new(
            support_profile.profile_id.clone(),
            protocol_profile_digest(support_profile),
        );
        let mut advertised_profiles = BoundedProfileRefVec::new();
        advertised_profiles
            .push(profile.clone())
            .expect("one profile is within protocol bounds");
        let metadata = PluginHelloMetadata {
            host_identity: HostExecutionIdentity::Plugin(manifest.host_identity),
            package_id: manifest.package_id,
            package_version: manifest.package_version,
            manifest_digest: ManifestDigest::from_bytes(*source.manifest_digest.as_bytes()),
            plugin_identity: HostExecutionIdentity::Plugin(manifest.plugin_identity),
            target_identity: manifest.target_identity,
            entrypoint: manifest.entrypoint,
        };
        Ok(Self {
            package_digest: source.package_digest,
            manifest_digest: source.manifest_digest,
            entrypoint_digest: source.entrypoint_digest,
            effective_class,
            effective_trust,
            protocol_profile_digest: source.protocol_profile_digest,
            trust_binding_digest: source.trust_binding_digest,
            activation: PluginActivationAuthority {
                profile,
                advertised_profiles,
                negotiation_snapshot: negotiation_snapshot(source, PluginGeneration::INITIAL),
                generation: PluginGeneration::INITIAL,
                metadata,
            },
        })
    }

    fn matches_content(&self, source: &PluginPackageSource) -> bool {
        self.package_digest == source.package_digest
            && self.manifest_digest == source.manifest_digest
            && self.entrypoint_digest == source.entrypoint_digest
            && self.protocol_profile_digest == source.protocol_profile_digest
            && self.trust_binding_digest == source.trust_binding_digest
    }

    #[allow(dead_code)] // Reserved for the crate-owned registry evolution boundary.
    fn at_generation(&self, generation: PluginGeneration) -> Self {
        let mut advanced = self.clone();
        advanced.activation.generation = generation;
        advanced.activation.negotiation_snapshot =
            negotiation_snapshot_from_authority(self, generation);
        advanced
    }
}

struct ParsedManifest {
    package_id: PluginId,
    package_version: PluginVersion,
    host_identity: PluginIdentity,
    plugin_identity: PluginIdentity,
    target_identity: TargetIdentity,
    entrypoint: EntrypointIdentity,
    file_table_digest: PluginDigest,
    protocol_profile_id: gocode_plugin_protocol::id::ProfileId,
    protocol_profile_digest: PluginDigest,
    files: Vec<DeclaredPackageFile>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct DeclaredPackageFile {
    path: String,
    kind: PluginPackageFileKind,
    size: u64,
    digest: PluginDigest,
}

/// The manifest/profile grammar is intentionally small, ordered and bounded.
/// It is a registry ingestion format, not a caller-controlled metadata API.
fn parse_manifest(bytes: &[u8]) -> Result<ParsedManifest, TrustedRegistryLoadError> {
    let text =
        core::str::from_utf8(bytes).map_err(|_| TrustedRegistryLoadError::MalformedAuthority)?;
    let mut lines = text.lines();
    if lines.next() != Some("GOCODE_PLUGIN_MANIFEST_V1") {
        return Err(TrustedRegistryLoadError::MalformedAuthority);
    }
    let package_id = PluginId::new(next_value(&mut lines, "package_id=")?)
        .map_err(|_| TrustedRegistryLoadError::MalformedAuthority)?;
    let package_version = PluginVersion::new(next_value(&mut lines, "package_version=")?)
        .map_err(|_| TrustedRegistryLoadError::MalformedAuthority)?;
    let host_identity = PluginIdentity::new(next_value(&mut lines, "host_identity=")?)
        .map_err(|_| TrustedRegistryLoadError::MalformedAuthority)?;
    let plugin_identity = PluginIdentity::new(next_value(&mut lines, "plugin_identity=")?)
        .map_err(|_| TrustedRegistryLoadError::MalformedAuthority)?;
    let target_identity = TargetIdentity::new(next_value(&mut lines, "target_identity=")?)
        .map_err(|_| TrustedRegistryLoadError::MalformedAuthority)?;
    let entrypoint = EntrypointIdentity::new(next_value(&mut lines, "entrypoint=")?)
        .map_err(|_| TrustedRegistryLoadError::MalformedAuthority)?;
    let file_table_digest = parse_tagged_digest(next_value(&mut lines, "file_table_digest=")?)?;
    let profile_declaration = next_value(&mut lines, "protocol_profile=")?;
    let (profile_id, profile_digest) = profile_declaration
        .split_once('|')
        .ok_or(TrustedRegistryLoadError::MalformedAuthority)?;
    let protocol_profile_id = gocode_plugin_protocol::id::ProfileId::new(profile_id)
        .map_err(|_| TrustedRegistryLoadError::MalformedAuthority)?;
    let protocol_profile_digest = parse_tagged_digest(profile_digest)?;
    let mut files = Vec::new();
    for line in lines {
        let declaration = line
            .strip_prefix("file=")
            .ok_or(TrustedRegistryLoadError::MalformedAuthority)?;
        files.push(parse_file_declaration(declaration)?);
        if files.len() > MAX_PACKAGE_FILES {
            return Err(TrustedRegistryLoadError::MalformedAuthority);
        }
    }
    if files.is_empty()
        || files.windows(2).any(|pair| pair[0].path >= pair[1].path)
        || files.iter().enumerate().any(|(index, file)| {
            files[index + 1..]
                .iter()
                .any(|other| file.path.eq_ignore_ascii_case(&other.path))
        })
    {
        return Err(TrustedRegistryLoadError::MalformedAuthority);
    }
    Ok(ParsedManifest {
        package_id,
        package_version,
        host_identity,
        plugin_identity,
        target_identity,
        entrypoint,
        file_table_digest,
        protocol_profile_id,
        protocol_profile_digest,
        files,
    })
}

fn parse_file_declaration(value: &str) -> Result<DeclaredPackageFile, TrustedRegistryLoadError> {
    let mut parts = value.split('|');
    let path = parts
        .next()
        .ok_or(TrustedRegistryLoadError::MalformedAuthority)?
        .to_owned();
    validate_package_path(&path).map_err(|_| TrustedRegistryLoadError::MalformedAuthority)?;
    let kind = match parts.next() {
        Some("data") => PluginPackageFileKind::Data,
        Some("executable") => PluginPackageFileKind::Executable,
        _ => return Err(TrustedRegistryLoadError::MalformedAuthority),
    };
    let size = parts
        .next()
        .ok_or(TrustedRegistryLoadError::MalformedAuthority)?
        .parse::<u64>()
        .map_err(|_| TrustedRegistryLoadError::MalformedAuthority)?;
    let digest = parse_tagged_digest(
        parts
            .next()
            .ok_or(TrustedRegistryLoadError::MalformedAuthority)?,
    )?;
    if parts.next().is_some() {
        return Err(TrustedRegistryLoadError::MalformedAuthority);
    }
    Ok(DeclaredPackageFile {
        path,
        kind,
        size,
        digest,
    })
}

fn parse_tagged_digest(value: &str) -> Result<PluginDigest, TrustedRegistryLoadError> {
    let hex = value
        .strip_prefix("sha256:")
        .ok_or(TrustedRegistryLoadError::MalformedAuthority)?;
    if hex.len() != 64
        || hex
            .as_bytes()
            .iter()
            .any(|byte| !byte.is_ascii_digit() && !matches!(*byte, b'a'..=b'f'))
    {
        return Err(TrustedRegistryLoadError::MalformedAuthority);
    }
    let mut bytes = [0; 32];
    for (index, chunk) in hex.as_bytes().chunks_exact(2).enumerate() {
        let high = hex_nibble(chunk[0]).ok_or(TrustedRegistryLoadError::MalformedAuthority)?;
        let low = hex_nibble(chunk[1]).ok_or(TrustedRegistryLoadError::MalformedAuthority)?;
        bytes[index] = (high << 4) | low;
    }
    Ok(PluginDigest::from_bytes(bytes))
}

fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    }
}

fn parse_profile(bytes: &[u8]) -> Result<ProtocolSupportProfile, TrustedRegistryLoadError> {
    let text =
        core::str::from_utf8(bytes).map_err(|_| TrustedRegistryLoadError::MalformedAuthority)?;
    let mut lines = text.lines();
    if lines.next() != Some("GOCODE_PLUGIN_PROFILE_V1") {
        return Err(TrustedRegistryLoadError::MalformedAuthority);
    }
    let profile_id =
        gocode_plugin_protocol::id::ProfileId::new(next_value(&mut lines, "profile_id=")?)
            .map_err(|_| TrustedRegistryLoadError::MalformedAuthority)?;
    let version = next_value(&mut lines, "version=")?;
    let (major, minor) = version
        .split_once('.')
        .ok_or(TrustedRegistryLoadError::MalformedAuthority)?;
    let version = ProtocolVersion::new(
        major
            .parse()
            .map_err(|_| TrustedRegistryLoadError::MalformedAuthority)?,
        minor
            .parse()
            .map_err(|_| TrustedRegistryLoadError::MalformedAuthority)?,
    );
    let bootstrap = parse_tagged_digest(next_value(&mut lines, "bootstrap_schema_digest=")?)?;
    let wire = parse_tagged_digest(next_value(&mut lines, "wire_contract_digest=")?)?;
    let schema = parse_tagged_digest(next_value(&mut lines, "session_schema_bundle_digest=")?)?;
    let feature_line = lines
        .next()
        .and_then(|line| line.strip_prefix("features="))
        .ok_or(TrustedRegistryLoadError::MalformedAuthority)?;
    let features = if feature_line.is_empty() {
        Vec::new()
    } else {
        feature_line.split(',').map(str::to_owned).collect()
    };
    let bounds = parse_tagged_digest(next_value(&mut lines, "bounds_profile_digest=")?)?;
    if lines.next().is_some() {
        return Err(TrustedRegistryLoadError::MalformedAuthority);
    }
    ProtocolSupportProfile::new(
        profile_id,
        version,
        BootstrapSchemaDigest::from_bytes(*bootstrap.as_bytes()),
        WireContractDigest::from_bytes(*wire.as_bytes()),
        SchemaBundleDigest::from_bytes(*schema.as_bytes()),
        BoundsProfileDigest::from_bytes(*bounds.as_bytes()),
        features,
    )
    .map_err(|_| TrustedRegistryLoadError::MalformedAuthority)
}

fn next_value<'a>(
    lines: &mut core::str::Lines<'a>,
    prefix: &str,
) -> Result<&'a str, TrustedRegistryLoadError> {
    let line = lines
        .next()
        .ok_or(TrustedRegistryLoadError::MalformedAuthority)?;
    let value = line
        .strip_prefix(prefix)
        .ok_or(TrustedRegistryLoadError::MalformedAuthority)?;
    if value.is_empty() {
        return Err(TrustedRegistryLoadError::MalformedAuthority);
    }
    // The returned slice is borrowed from the manifest bytes carried by `lines`.
    Ok(value)
}

fn negotiation_snapshot(
    source: &PluginPackageSource,
    generation: PluginGeneration,
) -> ProtocolNegotiationSnapshotDigest {
    let mut hasher = Sha256::new();
    hasher.update(NEGOTIATION_SNAPSHOT_DIGEST_DOMAIN);
    hasher.update(source.package_digest.as_bytes());
    hasher.update(source.manifest_digest.as_bytes());
    hasher.update(source.protocol_profile_digest.as_bytes());
    hasher.update(generation.get().to_be_bytes());
    nonzero_snapshot(hasher.finalize().into())
}

#[allow(dead_code)] // Reserved for the crate-owned registry evolution boundary.
fn negotiation_snapshot_from_authority(
    authority: &PluginPackageAuthority,
    generation: PluginGeneration,
) -> ProtocolNegotiationSnapshotDigest {
    let mut hasher = Sha256::new();
    hasher.update(NEGOTIATION_SNAPSHOT_DIGEST_DOMAIN);
    hasher.update(authority.package_digest.as_bytes());
    hasher.update(authority.manifest_digest.as_bytes());
    hasher.update(authority.protocol_profile_digest.as_bytes());
    hasher.update(generation.get().to_be_bytes());
    nonzero_snapshot(hasher.finalize().into())
}

fn nonzero_snapshot(mut bytes: [u8; 32]) -> ProtocolNegotiationSnapshotDigest {
    if bytes.iter().all(|byte| *byte == 0) {
        bytes[31] = 1;
    }
    ProtocolNegotiationSnapshotDigest::from_bytes(bytes)
}

/// Owned plugin content consumed by the capture boundary.
#[derive(PartialEq, Eq)]
pub struct PluginPackageContent {
    manifest_bytes: Box<[u8]>,
    files: Box<[PluginPackageFile]>,
    protocol_profile: ProtocolSupportProfile,
    trust_binding_bytes: Box<[u8]>,
}

impl PluginPackageContent {
    /// Takes bounded ownership of all package bytes before capture.
    pub fn try_new(
        package_bytes: Vec<u8>,
        manifest_bytes: Vec<u8>,
        entrypoint_bytes: Vec<u8>,
        protocol_profile_bytes: Vec<u8>,
        trust_binding_bytes: Vec<u8>,
    ) -> Result<Self, PluginPackageCaptureError> {
        if package_bytes.len() > MAX_PACKAGE_FILE_BYTES
            || entrypoint_bytes.len() > MAX_PACKAGE_FILE_BYTES
            || manifest_bytes.len() > MAX_MANIFEST_BYTES
            || protocol_profile_bytes.len() > MAX_PROFILE_OR_TRUST_BYTES
            || trust_binding_bytes.len() > MAX_PROFILE_OR_TRUST_BYTES
        {
            return Err(PluginPackageCaptureError::TooLarge);
        }
        let protocol_profile = parse_profile(&protocol_profile_bytes)
            .map_err(|_| PluginPackageCaptureError::InvalidProfile)?;
        let manifest = parse_manifest(&manifest_bytes)
            .map_err(|_| PluginPackageCaptureError::InvalidManifest)?;
        let files = vec![
            PluginPackageFile::try_new(
                manifest.entrypoint.as_str().to_owned(),
                PluginPackageFileKind::Executable,
                entrypoint_bytes,
            )?,
            PluginPackageFile::try_new(
                "package".to_owned(),
                PluginPackageFileKind::Data,
                package_bytes,
            )?,
        ];
        Self::try_from_files(manifest_bytes, files, protocol_profile, trust_binding_bytes)
    }

    /// Captures an arbitrary complete logical file set after exact manifest
    /// declaration equality and trusted bounds checks.
    pub fn try_from_files(
        manifest_bytes: Vec<u8>,
        mut files: Vec<PluginPackageFile>,
        protocol_profile: ProtocolSupportProfile,
        trust_binding_bytes: Vec<u8>,
    ) -> Result<Self, PluginPackageCaptureError> {
        if manifest_bytes.len() > MAX_MANIFEST_BYTES
            || protocol_profile.profile_bytes().len() > MAX_PROFILE_OR_TRUST_BYTES
            || trust_binding_bytes.len() > MAX_PROFILE_OR_TRUST_BYTES
            || files.is_empty()
            || files.len() > MAX_PACKAGE_FILES
        {
            return Err(PluginPackageCaptureError::TooLarge);
        }
        files.sort_by(|left, right| left.path.cmp(&right.path));
        if files.windows(2).any(|pair| pair[0].path >= pair[1].path)
            || files.iter().enumerate().any(|(index, file)| {
                files[index + 1..]
                    .iter()
                    .any(|other| file.path.eq_ignore_ascii_case(&other.path))
            })
        {
            return Err(PluginPackageCaptureError::DuplicatePath);
        }
        let retained_file_bytes = files
            .iter()
            .try_fold(0usize, |total, file| total.checked_add(file.bytes.len()));
        let total = retained_file_bytes
            .and_then(|value| value.checked_add(manifest_bytes.len()))
            .and_then(|value| value.checked_add(protocol_profile.profile_bytes().len()))
            .and_then(|value| value.checked_add(trust_binding_bytes.len()))
            .ok_or(PluginPackageCaptureError::TooLarge)?;
        if total > MAX_PACKAGE_RETAINED_BYTES {
            return Err(PluginPackageCaptureError::TooLarge);
        }
        let manifest = parse_manifest(&manifest_bytes)
            .map_err(|_| PluginPackageCaptureError::InvalidManifest)?;
        if manifest.protocol_profile_id != protocol_profile.profile_id
            || manifest.protocol_profile_digest
                != PluginDigest::from_bytes(protocol_profile_digest(&protocol_profile).into_bytes())
        {
            return Err(PluginPackageCaptureError::ProfileDeclarationMismatch);
        }
        validate_declared_files(&manifest, &files)?;
        Ok(Self {
            manifest_bytes: manifest_bytes.into_boxed_slice(),
            files: files.into_boxed_slice(),
            protocol_profile,
            trust_binding_bytes: trust_binding_bytes.into_boxed_slice(),
        })
    }

    #[cfg(test)]
    pub(crate) fn new(
        package_bytes: Vec<u8>,
        mut manifest_bytes: Vec<u8>,
        entrypoint_bytes: Vec<u8>,
        mut protocol_profile_bytes: Vec<u8>,
        trust_binding_bytes: Vec<u8>,
    ) -> Self {
        if parse_profile(&protocol_profile_bytes).is_err() {
            protocol_profile_bytes = upgrade_legacy_test_profile(&protocol_profile_bytes);
        }
        if parse_manifest(&manifest_bytes).is_err() {
            manifest_bytes = upgrade_legacy_test_manifest(
                &manifest_bytes,
                &package_bytes,
                &entrypoint_bytes,
                &protocol_profile_bytes,
            );
        }
        Self::try_new(
            package_bytes,
            manifest_bytes,
            entrypoint_bytes,
            protocol_profile_bytes,
            trust_binding_bytes,
        )
        .expect("test package content must satisfy the production capture boundary")
    }
}

#[cfg(test)]
fn upgrade_legacy_test_manifest(
    manifest: &[u8],
    package: &[u8],
    entrypoint: &[u8],
    profile: &[u8],
) -> Vec<u8> {
    let text = core::str::from_utf8(manifest).expect("test manifest is UTF-8");
    let entrypoint_path = text
        .lines()
        .find_map(|line| line.strip_prefix("entrypoint="))
        .expect("test manifest carries an entrypoint");
    let mut files = vec![
        PluginPackageFile::try_new(
            entrypoint_path.to_owned(),
            PluginPackageFileKind::Executable,
            entrypoint.to_vec(),
        )
        .unwrap(),
        PluginPackageFile::try_new(
            "package".to_owned(),
            PluginPackageFileKind::Data,
            package.to_vec(),
        )
        .unwrap(),
    ];
    files.sort_by(|left, right| left.path.cmp(&right.path));
    let table_digest = digest(FILE_TABLE_DIGEST_DOMAIN, &canonical_file_table(&files));
    let mut upgraded = text.trim_end().to_owned();
    upgraded.push('\n');
    upgraded.push_str("file_table_digest=");
    upgraded.push_str(&tagged_digest(table_digest));
    upgraded.push('\n');
    let profile = parse_profile(profile).expect("upgraded test profile is complete");
    upgraded.push_str("protocol_profile=");
    upgraded.push_str(profile.profile_id.as_str());
    upgraded.push('|');
    upgraded.push_str(&tagged_digest(PluginDigest::from_bytes(
        protocol_profile_digest(&profile).into_bytes(),
    )));
    upgraded.push('\n');
    for file in files {
        upgraded.push_str("file=");
        upgraded.push_str(file.path());
        upgraded.push('|');
        upgraded.push_str(match file.kind() {
            PluginPackageFileKind::Data => "data",
            PluginPackageFileKind::Executable => "executable",
        });
        upgraded.push('|');
        upgraded.push_str(&file.bytes().len().to_string());
        upgraded.push('|');
        upgraded.push_str(&tagged_digest(digest(FILE_DIGEST_DOMAIN, file.bytes())));
        upgraded.push('\n');
    }
    upgraded.into_bytes()
}

#[cfg(test)]
fn upgrade_legacy_test_profile(profile: &[u8]) -> Vec<u8> {
    let text = core::str::from_utf8(profile).expect("test profile is UTF-8");
    let profile_id = text
        .lines()
        .find_map(|line| line.strip_prefix("profile_id="))
        .expect("test profile carries an id");
    format!(
        "GOCODE_PLUGIN_PROFILE_V1\nprofile_id={profile_id}\nversion=1.0\nbootstrap_schema_digest=sha256:1111111111111111111111111111111111111111111111111111111111111111\nwire_contract_digest=sha256:2222222222222222222222222222222222222222222222222222222222222222\nsession_schema_bundle_digest=sha256:3333333333333333333333333333333333333333333333333333333333333333\nfeatures=bootstrap-v2\nbounds_profile_digest=sha256:4444444444444444444444444444444444444444444444444444444444444444\n"
    )
    .into_bytes()
}

#[cfg(test)]
fn tagged_digest(digest: PluginDigest) -> String {
    let mut value = String::with_capacity(71);
    value.push_str("sha256:");
    for byte in digest.as_bytes() {
        use core::fmt::Write as _;
        write!(&mut value, "{byte:02x}").expect("writing to String cannot fail");
    }
    value
}

fn validate_declared_files(
    manifest: &ParsedManifest,
    files: &[PluginPackageFile],
) -> Result<(), PluginPackageCaptureError> {
    if manifest.files.len() != files.len() {
        return Err(PluginPackageCaptureError::FileTableMismatch);
    }
    for (declared, captured) in manifest.files.iter().zip(files) {
        if declared.path.as_str() != captured.path.as_ref()
            || declared.kind != captured.kind
            || declared.size != captured.bytes.len() as u64
            || declared.digest != digest(FILE_DIGEST_DOMAIN, &captured.bytes)
        {
            return Err(PluginPackageCaptureError::FileTableMismatch);
        }
    }
    let entrypoint = files
        .iter()
        .find(|file| file.path.as_ref() == manifest.entrypoint.as_str());
    if !matches!(entrypoint, Some(file) if file.kind == PluginPackageFileKind::Executable) {
        return Err(PluginPackageCaptureError::EntrypointMismatch);
    }
    let file_table = canonical_file_table(files);
    if digest(FILE_TABLE_DIGEST_DOMAIN, &file_table) != manifest.file_table_digest {
        return Err(PluginPackageCaptureError::FileTableMismatch);
    }
    Ok(())
}

/// Kind of a captured logical package file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PluginPackageFileKind {
    /// Non-executable immutable resource.
    Data,
    /// Verified executable entrypoint or helper.
    Executable,
}

/// One immutable file accepted by the ADR-0015 package capture boundary.
#[derive(PartialEq, Eq)]
pub struct PluginPackageFile {
    path: Box<str>,
    kind: PluginPackageFileKind,
    bytes: Box<[u8]>,
}

impl PluginPackageFile {
    /// Validates the portable logical path and takes bounded ownership of bytes.
    pub fn try_new(
        path: String,
        kind: PluginPackageFileKind,
        bytes: Vec<u8>,
    ) -> Result<Self, PluginPackageCaptureError> {
        validate_package_path(&path)?;
        if bytes.len() > MAX_PACKAGE_FILE_BYTES {
            return Err(PluginPackageCaptureError::TooLarge);
        }
        Ok(Self {
            path: path.into_boxed_str(),
            kind,
            bytes: bytes.into_boxed_slice(),
        })
    }

    /// Canonical portable path.
    pub fn path(&self) -> &str {
        &self.path
    }
    /// Declared executable/data kind.
    pub const fn kind(&self) -> PluginPackageFileKind {
        self.kind
    }
    /// Exact immutable captured bytes.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}

fn validate_package_path(path: &str) -> Result<(), PluginPackageCaptureError> {
    if path.is_empty()
        || path.len() > MAX_PACKAGE_PATH_BYTES
        || path.starts_with('/')
        || path.starts_with("//")
        || path.contains('\\')
        || path.contains(':')
        || !path.is_ascii()
        || path.eq_ignore_ascii_case("gocode-plugin.toml")
    {
        return Err(PluginPackageCaptureError::InvalidPath);
    }
    let mut segment_count = 0usize;
    for segment in path.split('/') {
        segment_count += 1;
        if segment_count > MAX_PACKAGE_PATH_DEPTH {
            return Err(PluginPackageCaptureError::InvalidPath);
        }
        if segment.is_empty()
            || segment.len() > 128
            || matches!(segment, "." | "..")
            || !segment
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
            || !matches!(segment.as_bytes().first(), Some(byte) if byte.is_ascii_alphanumeric() || matches!(*byte, b'_' | b'-'))
            || !matches!(segment.as_bytes().last(), Some(byte) if byte.is_ascii_alphanumeric() || matches!(*byte, b'_' | b'-'))
        {
            return Err(PluginPackageCaptureError::InvalidPath);
        }
        let base = segment.split('.').next().unwrap_or_default();
        let upper = base.to_ascii_uppercase();
        if matches!(upper.as_str(), "CON" | "PRN" | "AUX" | "NUL")
            || (upper.len() == 4
                && (upper.starts_with("COM") || upper.starts_with("LPT"))
                && matches!(upper.as_bytes()[3], b'1'..=b'9'))
        {
            return Err(PluginPackageCaptureError::InvalidPath);
        }
    }
    Ok(())
}

/// Rejection at the bounded owned-content capture boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PluginPackageCaptureError {
    /// At least one caller-owned component exceeds the trusted capture bound.
    TooLarge,
    /// A logical package path violates ADR-0015 portable path rules.
    InvalidPath,
    /// The manifest could not be parsed under the pinned normalized grammar.
    InvalidManifest,
    /// The protocol profile was not a complete canonical ADR-0015 tuple.
    InvalidProfile,
    /// The manifest profile reference differs from the complete supplied tuple.
    ProfileDeclarationMismatch,
    /// Declared and captured file tables differ or contain a case-fold alias.
    FileTableMismatch,
    /// The selected entrypoint is absent or not executable.
    EntrypointMismatch,
    /// Two captured logical paths are identical or ASCII-case aliases.
    DuplicatePath,
}

/// Opaque, retained evidence captured from owned package content.
#[derive(PartialEq, Eq)]
pub struct PluginPackageSource {
    content: PluginPackageContent,
    package_digest: PluginDigest,
    manifest_digest: PluginDigest,
    entrypoint_digest: PluginDigest,
    declared_class: PluginClass,
    protocol_profile_digest: PluginDigest,
    trust_binding_digest: PluginDigest,
}

impl fmt::Debug for PluginPackageSource {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PluginPackageSource")
            .field("package_digest", &self.package_digest)
            .field("manifest_digest", &self.manifest_digest)
            .field("entrypoint_digest", &self.entrypoint_digest)
            .field("declared_class", &self.declared_class)
            .field("protocol_profile_digest", &self.protocol_profile_digest)
            .field("trust_binding_digest", &self.trust_binding_digest)
            .finish()
    }
}

/// Captures package evidence by hashing and retaining owned source bytes.
#[derive(Debug, Clone, Copy, Default)]
pub struct PluginPackageCapture;

impl PluginPackageCapture {
    /// Consumes source content and computes digests bound to its retained bytes.
    pub fn capture(
        content: PluginPackageContent,
        declared_class: PluginClass,
    ) -> PluginPackageSource {
        let manifest = parse_manifest(&content.manifest_bytes)
            .expect("PluginPackageContent validates the pinned manifest grammar");
        let manifest_bytes = canonical_manifest_bytes(&manifest);
        let manifest_digest = digest(MANIFEST_DIGEST_DOMAIN, &manifest_bytes);
        let entrypoint_digest = content
            .files
            .iter()
            .find(|file| file.path.as_ref() == manifest.entrypoint.as_str())
            .map(|file| digest(FILE_DIGEST_DOMAIN, &file.bytes))
            .expect("PluginPackageContent validates the executable entrypoint");
        let file_table_bytes = canonical_file_table(&content.files);
        let file_table_digest = digest(FILE_TABLE_DIGEST_DOMAIN, &file_table_bytes);
        let package_digest = package_digest(manifest_digest, file_table_digest);
        let protocol_profile_digest = PluginDigest::from_bytes(
            protocol_profile_digest(&content.protocol_profile).into_bytes(),
        );
        let trust_binding_digest =
            digest(TRUST_BINDING_DIGEST_DOMAIN, &content.trust_binding_bytes);

        PluginPackageSource {
            content,
            package_digest,
            manifest_digest,
            entrypoint_digest,
            declared_class,
            protocol_profile_digest,
            trust_binding_digest,
        }
    }
}

impl PluginPackageSource {
    /// Returns the computed package digest for comparison or audit.
    pub const fn package_digest(&self) -> PluginDigest {
        self.package_digest
    }
}

fn digest(domain: &[u8], bytes: &[u8]) -> PluginDigest {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update((bytes.len() as u64).to_be_bytes());
    hasher.update(bytes);
    PluginDigest::from_bytes(hasher.finalize().into())
}

fn package_digest(manifest: PluginDigest, table: PluginDigest) -> PluginDigest {
    let mut hasher = Sha256::new();
    hasher.update(PACKAGE_DIGEST_DOMAIN);
    hasher.update(MANIFEST_CONTRACT_DIGEST);
    hasher.update(manifest.as_bytes());
    hasher.update(table.as_bytes());
    PluginDigest::from_bytes(hasher.finalize().into())
}

fn canonical_manifest_bytes(parsed: &ParsedManifest) -> Vec<u8> {
    let mut enc = CborEncoder::new();
    enc.write_map_header(9);
    enc.write_unsigned(1);
    enc.write_text_string(parsed.package_id.as_str());
    enc.write_unsigned(2);
    enc.write_text_string(parsed.package_version.as_str());
    enc.write_unsigned(3);
    enc.write_text_string(parsed.host_identity.as_str());
    enc.write_unsigned(4);
    enc.write_text_string(parsed.plugin_identity.as_str());
    enc.write_unsigned(5);
    enc.write_text_string(parsed.target_identity.as_str());
    enc.write_unsigned(6);
    enc.write_text_string(parsed.entrypoint.as_str());
    enc.write_unsigned(7);
    enc.write_byte_string(parsed.file_table_digest.as_bytes());
    enc.write_unsigned(8);
    enc.write_array_header(2);
    enc.write_text_string(parsed.protocol_profile_id.as_str());
    enc.write_byte_string(parsed.protocol_profile_digest.as_bytes());
    enc.write_unsigned(9);
    enc.write_array_header(parsed.files.len() as u64);
    for file in &parsed.files {
        encode_file_table_entry(&mut enc, &file.path, file.kind, file.size, file.digest);
    }
    enc.into_bytes()
}

fn canonical_file_table(files: &[PluginPackageFile]) -> Vec<u8> {
    let mut enc = CborEncoder::new();
    enc.write_array_header(files.len() as u64);
    for file in files {
        encode_file_table_entry(
            &mut enc,
            &file.path,
            file.kind,
            file.bytes.len() as u64,
            digest(FILE_DIGEST_DOMAIN, &file.bytes),
        );
    }
    enc.into_bytes()
}

fn encode_file_table_entry(
    enc: &mut CborEncoder,
    path: &str,
    kind: PluginPackageFileKind,
    size: u64,
    file_digest: PluginDigest,
) {
    enc.write_map_header(4);
    enc.write_unsigned(1);
    enc.write_text_string(path);
    enc.write_unsigned(2);
    enc.write_text_string(match kind {
        PluginPackageFileKind::Data => "data",
        PluginPackageFileKind::Executable => "executable",
    });
    enc.write_unsigned(3);
    enc.write_unsigned(size);
    enc.write_unsigned(4);
    enc.write_byte_string(file_digest.as_bytes());
}

/// Fail-closed registry lookup boundary for an opaque package authority.
pub trait PluginAuthorityPort {
    /// Returns a verifier only when registry-owned authority is available.
    fn verifier_for(
        &self,
        source: &PluginPackageSource,
    ) -> Result<PluginPackageVerifier, PluginAuthorityPortError>;
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct ActiveBindingKey {
    activation_id: crate::PluginActivationId,
    generation: PluginGeneration,
    negotiation_snapshot: [u8; 32],
}

type HookDispatchRecord = ([u8; 32], Option<PluginHookDisposition>);
type HookDispatchRecords = BTreeMap<PluginHookDispatchJournalKey, HookDispatchRecord>;

#[derive(Debug, Default)]
struct InMemoryPluginHookDispatchJournal {
    records: Mutex<HookDispatchRecords>,
}

impl PluginHookDispatchJournal for InMemoryPluginHookDispatchJournal {
    fn claim_or_lookup(
        &self,
        key: &PluginHookDispatchJournalKey,
        request_digest: [u8; 32],
    ) -> Result<PluginHookDispatchJournalResult, PluginHookDispatchJournalError> {
        let mut records = self
            .records
            .lock()
            .map_err(|_| PluginHookDispatchJournalError::Unavailable)?;
        match records.get(key) {
            Some((stored_digest, outcome)) => Ok(PluginHookDispatchJournalResult::Existing {
                request_digest: *stored_digest,
                outcome: *outcome,
            }),
            None => {
                records.insert(key.clone(), (request_digest, None));
                Ok(PluginHookDispatchJournalResult::Fresh)
            }
        }
    }

    fn complete(
        &self,
        key: &PluginHookDispatchJournalKey,
        request_digest: [u8; 32],
        disposition: PluginHookDisposition,
    ) -> Result<(), PluginHookDispatchJournalError> {
        let mut records = self
            .records
            .lock()
            .map_err(|_| PluginHookDispatchJournalError::Unavailable)?;
        match records.get_mut(key) {
            Some((stored_digest, outcome))
                if stored_digest == &request_digest && outcome.is_none() =>
            {
                *outcome = Some(disposition);
                Ok(())
            }
            Some((stored_digest, Some(stored_outcome)))
                if stored_digest == &request_digest && stored_outcome == &disposition =>
            {
                Ok(())
            }
            Some(_) => Err(PluginHookDispatchJournalError::Conflict),
            None => Err(PluginHookDispatchJournalError::Unavailable),
        }
    }

    fn has_open_dispatches(&self) -> Result<bool, PluginHookDispatchJournalError> {
        Ok(self
            .records
            .lock()
            .map_err(|_| PluginHookDispatchJournalError::Unavailable)?
            .values()
            .any(|(_, outcome)| outcome.is_none()))
    }

    fn next_recovered_dispatch(
        &self,
    ) -> Result<Option<PluginHookRecoveredDispatch>, PluginHookDispatchJournalError> {
        Ok(None)
    }

    fn quarantine_recovered(
        &self,
        _: &PluginHookRecoveredDispatch,
    ) -> Result<(), PluginHookDispatchJournalError> {
        Err(PluginHookDispatchJournalError::Conflict)
    }
}

/// Immutable, registry-owned package authority lookup implementation.
pub struct PluginAuthorityRegistry {
    authorities: Box<[PluginPackageAuthority]>,
    active_bindings: Mutex<BTreeSet<ActiveBindingKey>>,
    hook_dispatch_journal: Arc<dyn PluginHookDispatchJournal>,
    transition_gate: Mutex<()>,
}

impl fmt::Debug for PluginAuthorityRegistry {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PluginAuthorityRegistry")
            .field("authorities", &self.authorities)
            .field("active_bindings", &self.active_bindings)
            .field("hook_dispatch_journal", &"<opaque durable journal>")
            .field("transition_gate", &self.transition_gate)
            .finish()
    }
}

impl Default for PluginAuthorityRegistry {
    fn default() -> Self {
        Self::empty()
    }
}

impl PluginAuthorityRegistry {
    pub(crate) fn with_active_transition<R>(
        &self,
        activation: &crate::PluginActivationSnapshot,
        operation: impl FnOnce() -> R,
    ) -> Result<R, ()> {
        let _transition = self.transition_gate.lock().map_err(|_| ())?;
        if !activation.is_dispatchable(self) {
            return Err(());
        }
        Ok(operation())
    }

    /// Creates a fail-closed registry with no package authorities.
    pub fn empty() -> Self {
        Self {
            authorities: Box::new([]),
            active_bindings: Mutex::new(BTreeSet::new()),
            hook_dispatch_journal: Arc::new(InMemoryPluginHookDispatchJournal::default()),
            transition_gate: Mutex::new(()),
        }
    }

    /// Loads the crate-owned immutable registry policy shipped with this host.
    pub fn built_in() -> Self {
        Self::built_in_with_hook_dispatch_journal(Arc::new(
            InMemoryPluginHookDispatchJournal::default(),
        ))
    }

    /// Loads built-in package policy with a repository-owned durable hook journal.
    ///
    /// Production composition must inject storage that survives process restart.
    pub fn built_in_with_hook_dispatch_journal(
        hook_dispatch_journal: Arc<dyn PluginHookDispatchJournal>,
    ) -> Self {
        let source = PluginPackageCapture::capture(
            PluginPackageContent::try_new(
                BUILTIN_PACKAGE_BYTES.to_vec(),
                BUILTIN_MANIFEST_BYTES.to_vec(),
                BUILTIN_ENTRYPOINT_BYTES.to_vec(),
                BUILTIN_PROTOCOL_PROFILE_BYTES.to_vec(),
                BUILTIN_TRUST_BINDING_BYTES.to_vec(),
            )
            .expect("embedded package satisfies the production capture boundary"),
            PluginClass::Extension,
        );
        Self::from_trusted_loader_with_hook_dispatch_journal(
            vec![
                PluginPackageAuthority::issue(
                    &source,
                    PluginClass::Extension,
                    PluginTrust::Restricted,
                )
                .expect("embedded manifest/profile are valid"),
            ],
            Arc::clone(&hook_dispatch_journal),
        )
        .unwrap_or_else(|_| Self {
            authorities: Box::new([]),
            active_bindings: Mutex::new(BTreeSet::new()),
            hook_dispatch_journal,
            transition_gate: Mutex::new(()),
        })
    }

    #[cfg(test)]
    fn from_trusted_loader(
        authorities: Vec<PluginPackageAuthority>,
    ) -> Result<Self, TrustedRegistryLoadError> {
        Self::from_trusted_loader_with_hook_dispatch_journal(
            authorities,
            Arc::new(InMemoryPluginHookDispatchJournal::default()),
        )
    }

    fn from_trusted_loader_with_hook_dispatch_journal(
        authorities: Vec<PluginPackageAuthority>,
        hook_dispatch_journal: Arc<dyn PluginHookDispatchJournal>,
    ) -> Result<Self, TrustedRegistryLoadError> {
        if authorities.is_empty()
            || authorities
                .iter()
                .enumerate()
                .any(|(index, authority)| authorities[index + 1..].contains(authority))
        {
            return Err(TrustedRegistryLoadError::InvalidSnapshot);
        }
        Ok(Self {
            authorities: authorities.into_boxed_slice(),
            active_bindings: Mutex::new(BTreeSet::new()),
            hook_dispatch_journal,
            transition_gate: Mutex::new(()),
        })
    }

    /// Advances the immutable registry snapshot without accepting caller-selected
    /// generation or metadata. Existing read leases become stale.
    pub fn advance(&mut self) -> Result<(), RegistryAdvanceError> {
        let _transition = self
            .transition_gate
            .lock()
            .map_err(|_| RegistryAdvanceError::Unavailable)?;
        if self
            .hook_dispatch_journal
            .has_open_dispatches()
            .map_err(|_| RegistryAdvanceError::Unavailable)?
        {
            return Err(RegistryAdvanceError::OpenDispatch);
        }
        let generation = self
            .authorities
            .first()
            .map(|authority| authority.activation.generation)
            .ok_or(RegistryAdvanceError::Unavailable)?;
        let next = PluginGeneration::new(
            generation
                .get()
                .checked_add(1)
                .ok_or(RegistryAdvanceError::Exhausted)?,
        )
        .ok_or(RegistryAdvanceError::Exhausted)?;
        if self
            .authorities
            .iter()
            .any(|authority| authority.activation.generation != generation)
        {
            return Err(RegistryAdvanceError::Unavailable);
        }
        self.authorities = self
            .authorities
            .iter()
            .map(|authority| authority.at_generation(next))
            .collect::<Vec<_>>()
            .into_boxed_slice();
        self.active_bindings
            .get_mut()
            .map_err(|_| RegistryAdvanceError::Unavailable)?
            .clear();
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)] // Returned only by the crate-owned registry evolution boundary.
pub enum RegistryAdvanceError {
    Unavailable,
    Exhausted,
    OpenDispatch,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TrustedRegistryLoadError {
    InvalidSnapshot,
    MalformedAuthority,
}

impl PluginAuthorityPort for PluginAuthorityRegistry {
    fn verifier_for(
        &self,
        source: &PluginPackageSource,
    ) -> Result<PluginPackageVerifier, PluginAuthorityPortError> {
        self.authorities
            .iter()
            .find(|authority| authority.matches_content(source))
            .cloned()
            .map(PluginPackageVerifier::new)
            .ok_or(PluginAuthorityPortError::Unavailable)
    }
}

impl PluginGenerationPort for PluginAuthorityRegistry {
    fn acquire_read_lease(
        &self,
        activation_id: &crate::PluginActivationId,
    ) -> Result<PluginGenerationReadLease, PluginGenerationPortError> {
        let generation = self
            .authorities
            .first()
            .map(|authority| authority.activation.generation)
            .ok_or(PluginGenerationPortError::Unavailable)?;
        Ok(PluginGenerationReadLease::issued(
            activation_id.clone(),
            generation,
        ))
    }

    fn ready_compare_and_set(
        &self,
        lease: &PluginGenerationReadLease,
    ) -> Result<(), PluginGenerationPortError> {
        match self.authorities.first() {
            Some(authority) if authority.activation.generation == lease.generation() => Ok(()),
            _ => Err(PluginGenerationPortError::Unavailable),
        }
    }

    fn publish_active(
        &self,
        lease: &PluginGenerationReadLease,
        negotiation_snapshot: ProtocolNegotiationSnapshotDigest,
    ) -> Result<PluginActiveFence, PluginGenerationPortError> {
        if !self.authorities.iter().any(|authority| {
            authority.activation.generation == lease.generation()
                && authority.activation.negotiation_snapshot == negotiation_snapshot
        }) {
            return Err(PluginGenerationPortError::Unavailable);
        }
        self.active_bindings
            .lock()
            .map_err(|_| PluginGenerationPortError::Unavailable)?
            .insert(ActiveBindingKey {
                activation_id: lease.activation_id().clone(),
                generation: lease.generation(),
                negotiation_snapshot: negotiation_snapshot.into_bytes(),
            });
        Ok(PluginActiveFence::issued(lease, negotiation_snapshot))
    }

    fn validate_active(&self, fence: &PluginActiveFence) -> Result<(), PluginGenerationPortError> {
        let current = self.authorities.iter().any(|authority| {
            fence.generation() == authority.activation.generation
                && fence.negotiation_snapshot() == authority.activation.negotiation_snapshot
        });
        let published = self
            .active_bindings
            .lock()
            .map_err(|_| PluginGenerationPortError::Unavailable)?
            .contains(&ActiveBindingKey {
                activation_id: fence.activation_id().clone(),
                generation: fence.generation(),
                negotiation_snapshot: fence.negotiation_snapshot().into_bytes(),
            });
        if current && published {
            Ok(())
        } else {
            Err(PluginGenerationPortError::Unavailable)
        }
    }
}

impl PluginHookDispatchAuthorityPort for PluginAuthorityRegistry {
    fn claim(
        &self,
        activation: &crate::PluginActivationSnapshot,
        definition: &crate::PluginHookDefinition,
        invocation: &crate::PluginHookInvocation,
        request_digest: [u8; 32],
    ) -> Result<PluginHookDispatchClaimResult, PluginHookDispatchError> {
        let _transition = self
            .transition_gate
            .lock()
            .map_err(|_| PluginHookDispatchError::AuthorityUnavailable)?;
        if definition.plugin_id() != activation.plugin_id() || !activation.is_dispatchable(self) {
            return Err(PluginHookDispatchError::AuthorityUnavailable);
        }
        let claim = PluginHookDispatchClaim::new(
            activation,
            definition.plugin_id().clone(),
            invocation.invocation_id().clone(),
            definition.hook_id().clone(),
            request_digest,
        );
        match self
            .hook_dispatch_journal
            .claim_or_lookup(claim.key(), request_digest)
            .map_err(map_hook_journal_error)?
        {
            PluginHookDispatchJournalResult::Existing {
                request_digest: stored_digest,
                ..
            } if stored_digest != request_digest => Err(PluginHookDispatchError::IntentConflict),
            PluginHookDispatchJournalResult::Existing {
                outcome: Some(outcome),
                ..
            } => Ok(PluginHookDispatchClaimResult::Existing(outcome)),
            PluginHookDispatchJournalResult::Existing { outcome: None, .. } => Ok(
                PluginHookDispatchClaimResult::Existing(PluginHookDisposition::Uncertain),
            ),
            PluginHookDispatchJournalResult::Fresh => {
                Ok(PluginHookDispatchClaimResult::Fresh(claim))
            }
        }
    }

    fn complete(
        &self,
        claim: PluginHookDispatchClaim,
        disposition: PluginHookDisposition,
    ) -> Result<(), PluginHookDispatchError> {
        self.hook_dispatch_journal
            .complete(claim.key(), *claim.request_digest(), disposition)
            .map_err(map_hook_journal_error)
    }

    fn quarantine_recovered(
        &self,
        recovered: &PluginHookRecoveredDispatch,
    ) -> Result<(), PluginHookDispatchError> {
        let _transition = self
            .transition_gate
            .lock()
            .map_err(|_| PluginHookDispatchError::AuthorityUnavailable)?;
        self.hook_dispatch_journal
            .quarantine_recovered(recovered)
            .map_err(map_hook_journal_error)
    }
}

fn map_hook_journal_error(error: PluginHookDispatchJournalError) -> PluginHookDispatchError {
    match error {
        PluginHookDispatchJournalError::Unavailable => {
            PluginHookDispatchError::AuthorityUnavailable
        }
        PluginHookDispatchJournalError::Conflict => PluginHookDispatchError::IntentConflict,
    }
}

/// Failure to obtain a registry-owned package verifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PluginAuthorityPortError {
    /// No registry authority was issued for the captured source.
    Unavailable,
}

impl fmt::Display for PluginAuthorityPortError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("plugin package authority unavailable")
    }
}

impl std::error::Error for PluginAuthorityPortError {}

/// Typed rejection of package authority verification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PluginPackageVerificationError {
    /// The package digest differed from the authority record.
    PackageDigestMismatch,
    /// The manifest digest differed from the authority record.
    ManifestDigestMismatch,
    /// The entrypoint digest differed from the authority record.
    EntrypointDigestMismatch,
    /// The manifest class differed from the registry-authorized class.
    DeclaredClassMismatch,
    /// The registry trust-binding evidence differed from the authority record.
    TrustBindingDigestMismatch,
    /// The complete protocol profile digest differed from the authority record.
    ProtocolProfileDigestMismatch,
}

impl fmt::Display for PluginPackageVerificationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::PackageDigestMismatch => "plugin package digest mismatch",
            Self::ManifestDigestMismatch => "plugin manifest digest mismatch",
            Self::EntrypointDigestMismatch => "plugin entrypoint digest mismatch",
            Self::DeclaredClassMismatch => "plugin declared class mismatch",
            Self::TrustBindingDigestMismatch => "plugin trust binding digest mismatch",
            Self::ProtocolProfileDigestMismatch => "plugin protocol profile digest mismatch",
        })
    }
}

impl std::error::Error for PluginPackageVerificationError {}

/// Verifies retained package evidence against one registry authority record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PluginPackageVerifier {
    authority: PluginPackageAuthority,
}

impl PluginPackageVerifier {
    fn new(authority: PluginPackageAuthority) -> Self {
        Self { authority }
    }

    /// Returns a verified package only when every authority component matches.
    pub fn verify(
        &self,
        source: PluginPackageSource,
    ) -> Result<VerifiedPluginPackage, PluginPackageVerificationError> {
        if source.manifest_digest != self.authority.manifest_digest {
            return Err(PluginPackageVerificationError::ManifestDigestMismatch);
        }
        if source.entrypoint_digest != self.authority.entrypoint_digest {
            return Err(PluginPackageVerificationError::EntrypointDigestMismatch);
        }
        if source.package_digest != self.authority.package_digest {
            return Err(PluginPackageVerificationError::PackageDigestMismatch);
        }
        if source.declared_class != self.authority.effective_class {
            return Err(PluginPackageVerificationError::DeclaredClassMismatch);
        }
        if source.trust_binding_digest != self.authority.trust_binding_digest {
            return Err(PluginPackageVerificationError::TrustBindingDigestMismatch);
        }
        if source.protocol_profile_digest != self.authority.protocol_profile_digest {
            return Err(PluginPackageVerificationError::ProtocolProfileDigestMismatch);
        }

        Ok(VerifiedPluginPackage {
            authority: self.authority.clone(),
            source,
        })
    }
}

/// Package authority proven against retained immutable source content.
#[derive(PartialEq, Eq)]
pub struct VerifiedPluginPackage {
    authority: PluginPackageAuthority,
    source: PluginPackageSource,
}

impl fmt::Debug for VerifiedPluginPackage {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VerifiedPluginPackage")
            .field("package_digest", &self.authority.package_digest)
            .field("effective_class", &self.authority.effective_class)
            .field("effective_trust", &self.authority.effective_trust)
            .finish()
    }
}

impl VerifiedPluginPackage {
    /// Returns the registry-derived effective plugin class.
    pub const fn effective_class(&self) -> PluginClass {
        self.authority.effective_class
    }

    /// Returns the registry-derived effective trust tier.
    pub const fn effective_trust(&self) -> PluginTrust {
        self.authority.effective_trust
    }

    /// Returns the digest bound to the retained verified package bytes.
    pub const fn package_digest(&self) -> PluginDigest {
        self.source.package_digest
    }

    /// Returns the protocol profile digest bound to the verified package authority.
    pub const fn protocol_profile_digest(&self) -> PluginDigest {
        self.authority.protocol_profile_digest
    }

    /// Returns the registry-owned current generation for this package.
    pub const fn generation(&self) -> crate::PluginGeneration {
        self.authority.activation.generation
    }

    /// Returns the immutable non-zero negotiation snapshot digest.
    pub const fn negotiation_snapshot(&self) -> ProtocolNegotiationSnapshotDigest {
        self.authority.activation.negotiation_snapshot
    }

    /// Returns the complete exact profile set advertised by this package.
    pub fn advertised_profiles(&self) -> BoundedProfileRefVec {
        self.authority.activation.advertised_profiles.clone()
    }

    pub(crate) fn selected_profile(&self) -> ProtocolProfileRef {
        self.authority.activation.profile.clone()
    }

    /// Returns the complete immutable PluginHello metadata bound by the registry.
    pub fn plugin_hello_metadata(&self) -> PluginHelloMetadata {
        self.authority.activation.metadata.clone()
    }
}

/// Immutable registry-owned fields expected in PluginHello.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PluginHelloMetadata {
    pub(crate) host_identity: HostExecutionIdentity,
    pub(crate) package_id: PluginId,
    pub(crate) package_version: PluginVersion,
    pub(crate) manifest_digest: ManifestDigest,
    pub(crate) plugin_identity: HostExecutionIdentity,
    pub(crate) target_identity: TargetIdentity,
    pub(crate) entrypoint: EntrypointIdentity,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn content() -> PluginPackageContent {
        PluginPackageContent::new(
            b"package-a".to_vec(),
            b"GOCODE_PLUGIN_MANIFEST_V1\npackage_id=package-a\npackage_version=1.0.0\nhost_identity=host-a\nplugin_identity=plugin-a\ntarget_identity=target-a\nentrypoint=entrypoint-a\n".to_vec(),
            b"entrypoint-a".to_vec(),
            b"GOCODE_PLUGIN_PROFILE_V1\nprofile_id=profile-a\n".to_vec(),
            b"trust-binding-a".to_vec(),
        )
    }

    fn declared_manifest(package: &[u8], entrypoint: &[u8]) -> Vec<u8> {
        upgrade_legacy_test_manifest(
            b"GOCODE_PLUGIN_MANIFEST_V1\npackage_id=package-a\npackage_version=1.0.0\nhost_identity=host-a\nplugin_identity=plugin-a\ntarget_identity=target-a\nentrypoint=entrypoint-a\n",
            package,
            entrypoint,
            &upgrade_legacy_test_profile(
                b"GOCODE_PLUGIN_PROFILE_V1\nprofile_id=profile-a\n",
            ),
        )
    }

    fn source() -> PluginPackageSource {
        PluginPackageCapture::capture(content(), PluginClass::Extension)
    }

    fn authority() -> PluginPackageAuthority {
        PluginPackageAuthority::issue(
            &source(),
            PluginClass::Extension,
            PluginTrust::RegistryVerified,
        )
        .unwrap()
    }

    fn registry() -> PluginAuthorityRegistry {
        PluginAuthorityRegistry::from_trusted_loader(vec![authority()]).unwrap()
    }

    #[test]
    fn registry_issues_a_verifier_from_its_opaque_authority() {
        let source = source();
        let verifier = registry().verifier_for(&source).unwrap();

        let verified = verifier.verify(source).unwrap();
        assert_eq!(verified.effective_trust(), PluginTrust::RegistryVerified);
    }

    #[test]
    fn declared_file_table_rejects_missing_extra_alias_and_digest_mismatch() {
        let package = b"package-a";
        let entrypoint = b"entrypoint-a";
        let manifest = declared_manifest(package, entrypoint);
        let profile_bytes =
            upgrade_legacy_test_profile(b"GOCODE_PLUGIN_PROFILE_V1\nprofile_id=profile-a\n");
        let profile = parse_profile(&profile_bytes).unwrap();
        let trust = b"trust-binding-a".to_vec();

        let missing = PluginPackageContent::try_from_files(
            manifest.clone(),
            vec![
                PluginPackageFile::try_new(
                    "entrypoint-a".to_owned(),
                    PluginPackageFileKind::Executable,
                    entrypoint.to_vec(),
                )
                .unwrap(),
            ],
            profile.clone(),
            trust.clone(),
        );
        assert!(matches!(
            missing,
            Err(PluginPackageCaptureError::FileTableMismatch)
        ));

        let extra = PluginPackageContent::try_from_files(
            manifest.clone(),
            vec![
                PluginPackageFile::try_new(
                    "entrypoint-a".to_owned(),
                    PluginPackageFileKind::Executable,
                    entrypoint.to_vec(),
                )
                .unwrap(),
                PluginPackageFile::try_new(
                    "package".to_owned(),
                    PluginPackageFileKind::Data,
                    package.to_vec(),
                )
                .unwrap(),
                PluginPackageFile::try_new(
                    "resource".to_owned(),
                    PluginPackageFileKind::Data,
                    vec![1],
                )
                .unwrap(),
            ],
            profile.clone(),
            trust.clone(),
        );
        assert!(matches!(
            extra,
            Err(PluginPackageCaptureError::FileTableMismatch)
        ));

        let alias = PluginPackageContent::try_from_files(
            manifest.clone(),
            vec![
                PluginPackageFile::try_new(
                    "entrypoint-a".to_owned(),
                    PluginPackageFileKind::Executable,
                    entrypoint.to_vec(),
                )
                .unwrap(),
                PluginPackageFile::try_new(
                    "Package".to_owned(),
                    PluginPackageFileKind::Data,
                    package.to_vec(),
                )
                .unwrap(),
                PluginPackageFile::try_new(
                    "package".to_owned(),
                    PluginPackageFileKind::Data,
                    package.to_vec(),
                )
                .unwrap(),
            ],
            profile.clone(),
            trust.clone(),
        );
        assert!(matches!(
            alias,
            Err(PluginPackageCaptureError::DuplicatePath)
        ));

        let mut mismatched_digest = manifest;
        let digest_offset = mismatched_digest
            .windows(b"sha256:".len())
            .rposition(|window| window == b"sha256:")
            .unwrap()
            + b"sha256:".len();
        mismatched_digest[digest_offset] = if mismatched_digest[digest_offset] == b'0' {
            b'1'
        } else {
            b'0'
        };
        let mismatch = PluginPackageContent::try_new(
            package.to_vec(),
            mismatched_digest,
            entrypoint.to_vec(),
            profile_bytes,
            trust,
        );
        assert!(matches!(
            mismatch,
            Err(PluginPackageCaptureError::FileTableMismatch)
        ));
    }

    #[test]
    fn manifest_binds_the_complete_protocol_profile_into_package_identity() {
        let first = PluginPackageCapture::capture(
            PluginPackageContent::new(
                b"package-a".to_vec(),
                b"GOCODE_PLUGIN_MANIFEST_V1\npackage_id=package-a\npackage_version=1.0.0\nhost_identity=host-a\nplugin_identity=plugin-a\ntarget_identity=target-a\nentrypoint=entrypoint-a\n".to_vec(),
                b"entrypoint-a".to_vec(),
                b"GOCODE_PLUGIN_PROFILE_V1\nprofile_id=profile-a\n".to_vec(),
                b"trust-binding-a".to_vec(),
            ),
            PluginClass::Extension,
        );
        let second = PluginPackageCapture::capture(
            PluginPackageContent::new(
                b"package-a".to_vec(),
                b"GOCODE_PLUGIN_MANIFEST_V1\npackage_id=package-a\npackage_version=1.0.0\nhost_identity=host-a\nplugin_identity=plugin-a\ntarget_identity=target-a\nentrypoint=entrypoint-a\n".to_vec(),
                b"entrypoint-a".to_vec(),
                b"GOCODE_PLUGIN_PROFILE_V1\nprofile_id=profile-b\n".to_vec(),
                b"trust-binding-a".to_vec(),
            ),
            PluginClass::Extension,
        );

        assert_ne!(first.manifest_digest, second.manifest_digest);
        assert_ne!(first.package_digest, second.package_digest);
        assert_ne!(
            first.protocol_profile_digest,
            second.protocol_profile_digest
        );
    }

    #[test]
    fn mutation_of_original_input_cannot_change_retained_verified_bytes() {
        let mut original_package = b"package-a".to_vec();
        let source = PluginPackageCapture::capture(
            PluginPackageContent::new(
                original_package.clone(),
                b"GOCODE_PLUGIN_MANIFEST_V1\npackage_id=package-a\npackage_version=1.0.0\nhost_identity=host-a\nplugin_identity=plugin-a\ntarget_identity=target-a\nentrypoint=entrypoint-a\n".to_vec(),
                b"entrypoint-a".to_vec(),
                b"GOCODE_PLUGIN_PROFILE_V1\nprofile_id=profile-a\n".to_vec(),
                b"trust-binding-a".to_vec(),
            ),
            PluginClass::Extension,
        );
        let expected_package = source
            .content
            .files
            .iter()
            .find(|file| file.path() == "package")
            .unwrap()
            .bytes
            .clone();
        original_package[0] = b'P';
        let verifier = registry().verifier_for(&source).unwrap();

        let verified = verifier.verify(source).unwrap();

        let retained_package = verified
            .source
            .content
            .files
            .iter()
            .find(|file| file.path() == "package")
            .unwrap();
        assert_eq!(retained_package.bytes, expected_package);
        assert_ne!(retained_package.bytes.as_ref(), original_package.as_slice());
    }

    #[test]
    fn changed_content_cannot_reuse_registry_verification() {
        let changed = PluginPackageCapture::capture(
            PluginPackageContent::new(
                b"package-b".to_vec(),
                b"GOCODE_PLUGIN_MANIFEST_V1\npackage_id=package-a\npackage_version=1.0.0\nhost_identity=host-a\nplugin_identity=plugin-a\ntarget_identity=target-a\nentrypoint=entrypoint-a\n".to_vec(),
                b"entrypoint-a".to_vec(),
                b"GOCODE_PLUGIN_PROFILE_V1\nprofile_id=profile-a\n".to_vec(),
                b"trust-binding-a".to_vec(),
            ),
            PluginClass::Extension,
        );

        assert_eq!(
            registry().verifier_for(&changed),
            Err(PluginAuthorityPortError::Unavailable)
        );
    }

    #[test]
    fn rejects_package_digest_substitution() {
        let mut source = source();
        source.package_digest = PluginDigest::from_bytes([9; 32]);

        assert_eq!(
            PluginPackageVerifier::new(authority()).verify(source),
            Err(PluginPackageVerificationError::PackageDigestMismatch)
        );
    }

    #[test]
    fn rejects_manifest_digest_substitution() {
        let mut source = source();
        source.manifest_digest = PluginDigest::from_bytes([8; 32]);

        assert_eq!(
            PluginPackageVerifier::new(authority()).verify(source),
            Err(PluginPackageVerificationError::ManifestDigestMismatch)
        );
    }

    #[test]
    fn rejects_entrypoint_digest_substitution() {
        let mut source = source();
        source.entrypoint_digest = PluginDigest::from_bytes([7; 32]);

        assert_eq!(
            PluginPackageVerifier::new(authority()).verify(source),
            Err(PluginPackageVerificationError::EntrypointDigestMismatch)
        );
    }

    #[test]
    fn rejects_declared_class_substitution() {
        let source = PluginPackageCapture::capture(content(), PluginClass::Security);

        assert_eq!(
            PluginPackageVerifier::new(authority()).verify(source),
            Err(PluginPackageVerificationError::DeclaredClassMismatch)
        );
    }

    #[test]
    fn rejects_trust_binding_substitution() {
        let source = PluginPackageCapture::capture(
            PluginPackageContent::new(
                b"package-a".to_vec(),
                b"GOCODE_PLUGIN_MANIFEST_V1\npackage_id=package-a\npackage_version=1.0.0\nhost_identity=host-a\nplugin_identity=plugin-a\ntarget_identity=target-a\nentrypoint=entrypoint-a\n".to_vec(),
                b"entrypoint-a".to_vec(),
                b"GOCODE_PLUGIN_PROFILE_V1\nprofile_id=profile-a\n".to_vec(),
                b"trust-binding-b".to_vec(),
            ),
            PluginClass::Extension,
        );

        assert_eq!(
            PluginPackageVerifier::new(authority()).verify(source),
            Err(PluginPackageVerificationError::TrustBindingDigestMismatch)
        );
    }

    #[test]
    fn rejects_protocol_profile_substitution() {
        let mut source = source();
        source.protocol_profile_digest = PluginDigest::from_bytes([6; 32]);

        assert_eq!(
            PluginPackageVerifier::new(authority()).verify(source),
            Err(PluginPackageVerificationError::ProtocolProfileDigestMismatch)
        );
    }

    #[test]
    fn registry_advance_invalidates_old_package_lease_and_reverifies_captured_content() {
        let mut registry = registry();
        let activation_id = crate::PluginActivationId::new("advance").unwrap();
        let old_package = registry
            .verifier_for(&source())
            .unwrap()
            .verify(source())
            .unwrap();
        let old_generation = old_package.generation();
        let old_snapshot = old_package.negotiation_snapshot();
        let old_lease =
            crate::PluginGenerationPort::acquire_read_lease(&registry, &activation_id).unwrap();

        registry.advance().unwrap();

        assert_eq!(
            crate::PluginGenerationPort::ready_compare_and_set(&registry, &old_lease),
            Err(crate::PluginGenerationPortError::Unavailable)
        );

        let current_package = registry
            .verifier_for(&source())
            .unwrap()
            .verify(source())
            .unwrap();
        let current_lease =
            crate::PluginGenerationPort::acquire_read_lease(&registry, &activation_id).unwrap();
        assert!(current_package.generation() > old_generation);
        assert_ne!(current_package.negotiation_snapshot(), old_snapshot);
        assert!(
            current_package
                .negotiation_snapshot()
                .as_bytes()
                .iter()
                .any(|byte| *byte != 0)
        );
        assert_eq!(
            crate::PluginGenerationPort::ready_compare_and_set(&registry, &current_lease),
            Ok(())
        );
    }

    #[test]
    fn active_validation_requires_exact_published_activation_binding() {
        let registry = registry();
        let package = registry
            .verifier_for(&source())
            .unwrap()
            .verify(source())
            .unwrap();
        let published_id = crate::PluginActivationId::new("published").unwrap();
        let unpublished_id = crate::PluginActivationId::new("unpublished").unwrap();
        let published_lease = registry.acquire_read_lease(&published_id).unwrap();
        let unpublished_lease = registry.acquire_read_lease(&unpublished_id).unwrap();
        let unpublished =
            PluginActiveFence::issued(&unpublished_lease, package.negotiation_snapshot());
        assert_eq!(
            registry.validate_active(&unpublished),
            Err(PluginGenerationPortError::Unavailable)
        );

        let published = registry
            .publish_active(&published_lease, package.negotiation_snapshot())
            .unwrap();
        assert!(registry.validate_active(&published).is_ok());
        assert_eq!(
            registry.validate_active(&unpublished),
            Err(PluginGenerationPortError::Unavailable)
        );
    }
}
