use core::fmt;

use sha2::{Digest, Sha256};

use crate::{
    PluginClass, PluginDigest, PluginGeneration, PluginGenerationPort, PluginGenerationPortError,
    PluginGenerationReadLease, PluginTrust,
};
use gocode_plugin_protocol::bootstrap::HostExecutionIdentity;
use gocode_plugin_protocol::digest::{
    ManifestDigest, ProfileDigest, ProtocolNegotiationSnapshotDigest,
};
use gocode_plugin_protocol::id::{
    EntrypointIdentity, PluginId, PluginIdentity, PluginVersion, ProfileId, TargetIdentity,
};
use gocode_plugin_protocol::profile::{BoundedProfileRefVec, ProtocolProfileRef};

const PACKAGE_DIGEST_DOMAIN: &[u8] = b"GOCODE_PLUGIN_PACKAGE_V1\0";
const MANIFEST_DIGEST_DOMAIN: &[u8] = b"GOCODE_PLUGIN_MANIFEST_V1\0";
const ENTRYPOINT_DIGEST_DOMAIN: &[u8] = b"GOCODE_PLUGIN_ENTRYPOINT_V1\0";
const PROTOCOL_PROFILE_DIGEST_DOMAIN: &[u8] = b"GOCODE_PLUGIN_PROTOCOL_PROFILE_V1\0";
const TRUST_BINDING_DIGEST_DOMAIN: &[u8] = b"GOCODE_PLUGIN_TRUST_BINDING_V1\0";
const NEGOTIATION_SNAPSHOT_DIGEST_DOMAIN: &[u8] = b"GOCODE_PLUGIN_NEGOTIATION_SNAPSHOT_V1\0";
const BUILTIN_PACKAGE_BYTES: &[u8] = b"gocode-plugin-host/builtin-package-v1";
const BUILTIN_MANIFEST_BYTES: &[u8] = b"GOCODE_PLUGIN_MANIFEST_V1\npackage_id=builtin\npackage_version=1.0.0\nhost_identity=host\nplugin_identity=plugin\ntarget_identity=target\nentrypoint=entrypoint\n";
const BUILTIN_ENTRYPOINT_BYTES: &[u8] = b"gocode-plugin-host/builtin-entrypoint-v1";
const BUILTIN_PROTOCOL_PROFILE_BYTES: &[u8] =
    b"GOCODE_PLUGIN_PROFILE_V1\nprofile_id=builtin-profile-v2\n";
const BUILTIN_TRUST_BINDING_BYTES: &[u8] = b"gocode-plugin-host/builtin-trust-binding-v1";
/// Trusted capture bound before retaining any untrusted package component.
pub const MAX_CAPTURE_COMPONENT_BYTES: usize = 64 * 1024;

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
        let profile_id = parse_profile(&source.content.protocol_profile_bytes)?;
        let profile = ProtocolProfileRef::new(
            profile_id,
            ProfileDigest::from_bytes(*source.protocol_profile_digest.as_bytes()),
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
    if lines.next().is_some() {
        return Err(TrustedRegistryLoadError::MalformedAuthority);
    }
    Ok(ParsedManifest {
        package_id,
        package_version,
        host_identity,
        plugin_identity,
        target_identity,
        entrypoint,
    })
}

fn parse_profile(bytes: &[u8]) -> Result<ProfileId, TrustedRegistryLoadError> {
    let text =
        core::str::from_utf8(bytes).map_err(|_| TrustedRegistryLoadError::MalformedAuthority)?;
    let mut lines = text.lines();
    if lines.next() != Some("GOCODE_PLUGIN_PROFILE_V1") {
        return Err(TrustedRegistryLoadError::MalformedAuthority);
    }
    let profile = ProfileId::new(next_value(&mut lines, "profile_id=")?)
        .map_err(|_| TrustedRegistryLoadError::MalformedAuthority)?;
    if lines.next().is_some() {
        return Err(TrustedRegistryLoadError::MalformedAuthority);
    }
    Ok(profile)
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
    package_bytes: Box<[u8]>,
    manifest_bytes: Box<[u8]>,
    entrypoint_bytes: Box<[u8]>,
    protocol_profile_bytes: Box<[u8]>,
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
        if [
            package_bytes.len(),
            manifest_bytes.len(),
            entrypoint_bytes.len(),
            protocol_profile_bytes.len(),
            trust_binding_bytes.len(),
        ]
        .into_iter()
        .any(|len| len > MAX_CAPTURE_COMPONENT_BYTES)
        {
            return Err(PluginPackageCaptureError::TooLarge);
        }
        Ok(Self::new(
            package_bytes,
            manifest_bytes,
            entrypoint_bytes,
            protocol_profile_bytes,
            trust_binding_bytes,
        ))
    }
    /// Takes ownership of all package bytes before capture.
    pub fn new(
        package_bytes: Vec<u8>,
        manifest_bytes: Vec<u8>,
        entrypoint_bytes: Vec<u8>,
        protocol_profile_bytes: Vec<u8>,
        trust_binding_bytes: Vec<u8>,
    ) -> Self {
        Self {
            package_bytes: package_bytes.into_boxed_slice(),
            manifest_bytes: manifest_bytes.into_boxed_slice(),
            entrypoint_bytes: entrypoint_bytes.into_boxed_slice(),
            protocol_profile_bytes: protocol_profile_bytes.into_boxed_slice(),
            trust_binding_bytes: trust_binding_bytes.into_boxed_slice(),
        }
    }
}

/// Rejection at the bounded owned-content capture boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PluginPackageCaptureError {
    /// At least one caller-owned component exceeds the trusted capture bound.
    TooLarge,
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
        let package_digest = digest(PACKAGE_DIGEST_DOMAIN, &content.package_bytes);
        let manifest_digest = digest(MANIFEST_DIGEST_DOMAIN, &content.manifest_bytes);
        let entrypoint_digest = digest(ENTRYPOINT_DIGEST_DOMAIN, &content.entrypoint_bytes);
        let protocol_profile_digest = digest(
            PROTOCOL_PROFILE_DIGEST_DOMAIN,
            &content.protocol_profile_bytes,
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

/// Fail-closed registry lookup boundary for an opaque package authority.
pub trait PluginAuthorityPort {
    /// Returns a verifier only when registry-owned authority is available.
    fn verifier_for(
        &self,
        source: &PluginPackageSource,
    ) -> Result<PluginPackageVerifier, PluginAuthorityPortError>;
}

/// Immutable, registry-owned package authority lookup implementation.
#[derive(Debug, Default)]
pub struct PluginAuthorityRegistry {
    authorities: Box<[PluginPackageAuthority]>,
}

impl PluginAuthorityRegistry {
    /// Creates a fail-closed registry with no package authorities.
    pub fn empty() -> Self {
        Self {
            authorities: Box::new([]),
        }
    }

    /// Loads the crate-owned immutable registry policy shipped with this host.
    pub fn built_in() -> Self {
        let source = PluginPackageCapture::capture(
            PluginPackageContent::new(
                BUILTIN_PACKAGE_BYTES.to_vec(),
                BUILTIN_MANIFEST_BYTES.to_vec(),
                BUILTIN_ENTRYPOINT_BYTES.to_vec(),
                BUILTIN_PROTOCOL_PROFILE_BYTES.to_vec(),
                BUILTIN_TRUST_BINDING_BYTES.to_vec(),
            ),
            PluginClass::Extension,
        );
        Self::from_trusted_loader(vec![
            PluginPackageAuthority::issue(&source, PluginClass::Extension, PluginTrust::Restricted)
                .expect("embedded manifest/profile are valid"),
        ])
        .unwrap_or_else(|_| Self::empty())
    }

    fn from_trusted_loader(
        authorities: Vec<PluginPackageAuthority>,
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
        })
    }

    /// Advances the immutable registry snapshot without accepting caller-selected
    /// generation or metadata. Existing read leases become stale.
    pub fn advance(&mut self) -> Result<(), RegistryAdvanceError> {
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
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)] // Returned only by the crate-owned registry evolution boundary.
pub enum RegistryAdvanceError {
    Unavailable,
    Exhausted,
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
        if source.package_digest != self.authority.package_digest {
            return Err(PluginPackageVerificationError::PackageDigestMismatch);
        }
        if source.manifest_digest != self.authority.manifest_digest {
            return Err(PluginPackageVerificationError::ManifestDigestMismatch);
        }
        if source.entrypoint_digest != self.authority.entrypoint_digest {
            return Err(PluginPackageVerificationError::EntrypointDigestMismatch);
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
        let expected_package = source.content.package_bytes.clone();
        original_package[0] = b'P';
        let verifier = registry().verifier_for(&source).unwrap();

        let verified = verifier.verify(source).unwrap();

        assert_eq!(verified.source.content.package_bytes, expected_package);
        assert_ne!(
            verified.source.content.package_bytes.as_ref(),
            original_package.as_slice()
        );
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
        let source = PluginPackageCapture::capture(
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
            PluginPackageVerifier::new(authority()).verify(source),
            Err(PluginPackageVerificationError::PackageDigestMismatch)
        );
    }

    #[test]
    fn rejects_manifest_digest_substitution() {
        let source = PluginPackageCapture::capture(
            PluginPackageContent::new(
                b"package-a".to_vec(),
                b"manifest-b".to_vec(),
                b"entrypoint-a".to_vec(),
                b"profile-a".to_vec(),
                b"trust-binding-a".to_vec(),
            ),
            PluginClass::Extension,
        );

        assert_eq!(
            PluginPackageVerifier::new(authority()).verify(source),
            Err(PluginPackageVerificationError::ManifestDigestMismatch)
        );
    }

    #[test]
    fn rejects_entrypoint_digest_substitution() {
        let source = PluginPackageCapture::capture(
            PluginPackageContent::new(
                b"package-a".to_vec(),
                b"GOCODE_PLUGIN_MANIFEST_V1\npackage_id=package-a\npackage_version=1.0.0\nhost_identity=host-a\nplugin_identity=plugin-a\ntarget_identity=target-a\nentrypoint=entrypoint-a\n".to_vec(),
                b"entrypoint-b".to_vec(),
                b"GOCODE_PLUGIN_PROFILE_V1\nprofile_id=profile-a\n".to_vec(),
                b"trust-binding-a".to_vec(),
            ),
            PluginClass::Extension,
        );

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
        let source = PluginPackageCapture::capture(
            PluginPackageContent::new(
                b"package-a".to_vec(),
                b"GOCODE_PLUGIN_MANIFEST_V1\npackage_id=package-a\npackage_version=1.0.0\nhost_identity=host-a\nplugin_identity=plugin-a\ntarget_identity=target-a\nentrypoint=entrypoint-a\n".to_vec(),
                b"entrypoint-a".to_vec(),
                b"profile-b".to_vec(),
                b"trust-binding-a".to_vec(),
            ),
            PluginClass::Extension,
        );

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
}
