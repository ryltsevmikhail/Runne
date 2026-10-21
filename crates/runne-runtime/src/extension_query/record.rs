use super::identity::*;
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(super) enum ExtensionKind {
    Mcp,
    Plugin,
}
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(super) struct ExtensionKey {
    pub(super) kind: ExtensionKind,
    pub(super) id: RegistrationId,
}
#[derive(Clone)]
pub(super) enum Query {
    List { kind: Option<ExtensionKind> },
    Get { key: ExtensionKey },
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum TransportClass {
    LocalContained,
    RemoteBrokered,
}
#[derive(Clone, PartialEq, Eq)]
pub(super) struct RequiredMcpProfile {
    pub(super) id: ProfileId,
    pub(super) revision: u64,
}
#[derive(Clone, PartialEq, Eq)]
pub(super) struct DeclaredPackage {
    pub(super) version: PackageVersion,
    pub(super) digest: [u8; 32],
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum McpAvailability {
    SdkProfileUnavailable,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum PluginAvailability {
    ActivationNotIntegrated,
}
#[derive(Clone, PartialEq, Eq)]
pub(super) enum ConfiguredMetadata {
    Mcp {
        id: RegistrationId,
        record_revision: u64,
        transport: TransportClass,
        required_profile: RequiredMcpProfile,
        availability: McpAvailability,
    },
    Plugin {
        id: RegistrationId,
        record_revision: u64,
        package: DeclaredPackage,
        availability: PluginAvailability,
    },
}
impl ConfiguredMetadata {
    pub(super) fn key(&self) -> ExtensionKey {
        match self {
            Self::Mcp { id, .. } => ExtensionKey {
                kind: ExtensionKind::Mcp,
                id: id.clone(),
            },
            Self::Plugin { id, .. } => ExtensionKey {
                kind: ExtensionKind::Plugin,
                id: id.clone(),
            },
        }
    }
}
/// Provenance: AcceptedConfigSnapshotV1. CONFIDENTIAL/INTERNAL, not export-safe.
#[derive(Clone)]
pub(super) struct MetadataReply {
    pub(super) scope: RegistryScope,
    pub(super) owner_epoch: u64,
    pub(super) snapshot: SnapshotVersion,
    pub(super) records: Vec<ConfiguredMetadata>,
}
pub(super) fn mcp_availability(
    enabled: bool,
) -> Result<McpAvailability, super::MetadataQueryError> {
    if enabled {
        Err(super::MetadataQueryError::UnsupportedContract)
    } else {
        Ok(McpAvailability::SdkProfileUnavailable)
    }
}
opaque!(
    ExtensionKey,
    Query,
    RequiredMcpProfile,
    DeclaredPackage,
    ConfiguredMetadata,
    MetadataReply
);
