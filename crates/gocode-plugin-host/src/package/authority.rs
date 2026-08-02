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
