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
