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

include!("package/authority.rs");
include!("package/parsing.rs");
include!("package/content.rs");
include!("package/capture.rs");
include!("package/registry.rs");
include!("package/registry_ports.rs");
include!("package/verifier.rs");

#[cfg(test)]
mod tests {
    include!("package/tests_part1.rs");
    include!("package/tests_part2.rs");
}
