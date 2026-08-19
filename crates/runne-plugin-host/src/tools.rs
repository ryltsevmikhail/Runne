//! Plugin tool publication through the project ToolRegistry.

use runne_plugin_protocol::id::PluginId;
use runne_tools::{
    InvalidToolDefinition, SandboxProfile, ToolAdmissionPort, ToolClass, ToolDefinition,
    ToolDispatchBinding, ToolDispatchRequest, ToolExecutionHandle, ToolExecutorPort, ToolGateway,
    ToolGatewayError, ToolId, ToolRef, ToolRegistry, ToolRegistryError, ToolVersion,
    ToolsetSnapshot,
};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::{
    PluginActivationId, PluginActivationSnapshot, PluginAuthorityRegistry, PluginDigest,
    PluginGeneration, PluginGenerationPort, VerifiedPluginPackage,
};

/// Maximum tool descriptors in one verified plugin publication.
pub const MAX_PLUGIN_TOOL_DEFINITIONS: usize = 4096;

/// Immutable plugin tool descriptor accepted from a verified descriptor set.
#[derive(Debug, Clone, PartialEq)]
pub struct PluginToolDescriptor {
    plugin_id: PluginId,
    tool_id: ToolId,
    version: ToolVersion,
    input_schema: Value,
}

impl PluginToolDescriptor {
    /// Creates a package-owned descriptor; schema validation occurs before publication.
    pub const fn new(
        plugin_id: PluginId,
        tool_id: ToolId,
        version: ToolVersion,
        input_schema: Value,
    ) -> Self {
        Self {
            plugin_id,
            tool_id,
            version,
            input_schema,
        }
    }
}

/// Failure while preparing or atomically publishing plugin tools.
#[derive(Debug)]
pub enum PluginToolPublicationError {
    /// Publication requires an active, descriptor-bound activation cutover.
    ActiveDescriptorProofRequired,
    /// Descriptor count exceeded the trusted immutable snapshot bound.
    TooManyDefinitions,
    /// A descriptor owner differed from the exact verified package.
    OwnerMismatch,
    /// ToolID did not use the exact package-owned namespace.
    NamespaceMismatch,
    /// A descriptor failed project-owned schema validation.
    InvalidDefinition(InvalidToolDefinition),
    /// Atomic registry publication rejected the descriptor set.
    Registry(ToolRegistryError),
    /// Descriptor authority rejected the candidate snapshot.
    DescriptorUnverified,
    /// Activation/package/generation binding was stale or mismatched.
    StaleActivation,
}

/// Failure while carrying an activation-bound tool through ToolGateway.
#[derive(Debug)]
pub enum PluginToolDispatchError {
    /// Activation or descriptor binding was stale before effect admission.
    StaleActivation,
    /// ToolGateway rejected or could not establish a trustworthy disposition.
    Gateway(ToolGatewayError),
}

/// Validates owner/namespace, then atomically registers and snapshots the exact
/// verified plugin tool versions.
pub fn publish_plugin_tools(
    _: &VerifiedPluginPackage,
    _: Vec<PluginToolDescriptor>,
    _: &mut ToolRegistry,
) -> Result<ToolsetSnapshot, PluginToolPublicationError> {
    Err(PluginToolPublicationError::ActiveDescriptorProofRequired)
}

fn prepare_plugin_tools(
    package: &VerifiedPluginPackage,
    descriptors: Vec<PluginToolDescriptor>,
) -> Result<Vec<ToolDefinition>, PluginToolPublicationError> {
    if descriptors.len() > MAX_PLUGIN_TOOL_DEFINITIONS {
        return Err(PluginToolPublicationError::TooManyDefinitions);
    }
    let package_id = package.plugin_hello_metadata().package_id;
    let namespace = format!("{}::", package_id.as_str());
    let mut definitions = Vec::with_capacity(descriptors.len());
    for descriptor in descriptors {
        if descriptor.plugin_id != package_id {
            return Err(PluginToolPublicationError::OwnerMismatch);
        }
        if !descriptor.tool_id.as_str().starts_with(&namespace) {
            return Err(PluginToolPublicationError::NamespaceMismatch);
        }
        definitions.push(
            ToolDefinition::new(
                descriptor.tool_id,
                descriptor.version,
                ToolClass::Plugin,
                descriptor.input_schema,
                SandboxProfile::PluginHost,
            )
            .map_err(PluginToolPublicationError::InvalidDefinition)?,
        );
    }
    Ok(definitions)
}

/// Trusted manifest/handshake authority for a complete tool descriptor snapshot.
pub trait PluginToolDescriptorAuthorityPort {
    /// Accepts only the exact descriptor digest pinned by trusted evidence.
    fn accepts(
        &self,
        activation: &PluginActivationSnapshot,
        descriptor_snapshot_digest: [u8; 32],
    ) -> bool;
}

/// Opaque verified tool descriptor snapshot bound to one activation revision.
pub struct VerifiedPluginToolDescriptors {
    activation_id: PluginActivationId,
    package_digest: PluginDigest,
    generation: PluginGeneration,
    descriptor_snapshot_digest: [u8; 32],
    definitions: Vec<ToolDefinition>,
}

/// Validates and freezes a complete tool descriptor candidate without making
/// it routable.
pub fn verify_plugin_tool_descriptors(
    package: &VerifiedPluginPackage,
    activation: &PluginActivationSnapshot,
    generations: &dyn PluginGenerationPort,
    descriptors: Vec<PluginToolDescriptor>,
    authority: &dyn PluginToolDescriptorAuthorityPort,
) -> Result<VerifiedPluginToolDescriptors, PluginToolPublicationError> {
    if package.package_digest() != activation.package_digest()
        || !activation.is_dispatchable(generations)
    {
        return Err(PluginToolPublicationError::StaleActivation);
    }
    let descriptor_snapshot_digest = tool_descriptor_digest(&descriptors);
    let definitions = prepare_plugin_tools(package, descriptors)?;
    if !authority.accepts(activation, descriptor_snapshot_digest) {
        return Err(PluginToolPublicationError::DescriptorUnverified);
    }
    Ok(VerifiedPluginToolDescriptors {
        activation_id: activation.activation_id().clone(),
        package_digest: activation.package_digest(),
        generation: activation.generation(),
        descriptor_snapshot_digest,
        definitions,
    })
}

/// Activation-bound registry wrapper that fails closed after generation
/// cutover or activation mismatch.
pub struct ActivePluginToolset {
    activation_id: PluginActivationId,
    package_digest: PluginDigest,
    generation: PluginGeneration,
    descriptor_snapshot_digest: [u8; 32],
    registry: ToolRegistry,
    snapshot: ToolsetSnapshot,
}

impl ActivePluginToolset {
    /// Exact descriptor digest accepted before activation cutover.
    pub const fn descriptor_snapshot_digest(&self) -> &[u8; 32] {
        &self.descriptor_snapshot_digest
    }

    /// Creates a gateway binding only while the exact activation remains fresh.
    ///
    /// The underlying definition is never exposed, so callers cannot clone a
    /// point-in-time resolution into an independently routable stale tool.
    pub(crate) fn bind_dispatch(
        &self,
        tool_ref: &ToolRef,
        activation: &PluginActivationSnapshot,
        generations: &dyn PluginGenerationPort,
    ) -> Result<ToolDispatchBinding, PluginToolPublicationError> {
        if self.activation_id != *activation.activation_id()
            || self.package_digest != activation.package_digest()
            || self.generation != activation.generation()
            || !activation.is_dispatchable(generations)
        {
            return Err(PluginToolPublicationError::StaleActivation);
        }
        self.registry
            .resolve(tool_ref)
            .map_err(PluginToolPublicationError::Registry)?;
        Ok(ToolDispatchBinding::new(
            tool_ref.clone(),
            self.activation_id.as_str().to_owned(),
            *self.package_digest.as_bytes(),
            self.generation.get(),
            self.descriptor_snapshot_digest,
        ))
    }

    /// Revalidates the exact binding and holds generation cutover through the
    /// ToolGateway effect claim and executor start boundary.
    pub fn dispatch_via_gateway<A, E>(
        &self,
        tool_ref: &ToolRef,
        activation: &PluginActivationSnapshot,
        authority: &PluginAuthorityRegistry,
        gateway: &ToolGateway<A, E>,
        invocation_id: String,
        request_digest: [u8; 32],
    ) -> Result<ToolExecutionHandle, PluginToolDispatchError>
    where
        A: ToolAdmissionPort,
        E: ToolExecutorPort,
    {
        authority
            .with_active_transition(activation, || {
                let binding = self
                    .bind_dispatch(tool_ref, activation, authority)
                    .map_err(|_| PluginToolDispatchError::StaleActivation)?;
                gateway
                    .dispatch(ToolDispatchRequest {
                        invocation_id,
                        request_digest,
                        binding,
                    })
                    .map_err(PluginToolDispatchError::Gateway)
            })
            .map_err(|_| PluginToolDispatchError::StaleActivation)?
    }

    /// Exact immutable tool refs captured at activation cutover.
    pub const fn snapshot(&self) -> &ToolsetSnapshot {
        &self.snapshot
    }
}

/// Atomically creates a routable activation-local ToolRegistry from a verified
/// descriptor snapshot.
pub fn activate_plugin_tools(
    verified: VerifiedPluginToolDescriptors,
    activation: &PluginActivationSnapshot,
    generations: &dyn PluginGenerationPort,
) -> Result<ActivePluginToolset, PluginToolPublicationError> {
    if verified.activation_id != *activation.activation_id()
        || verified.package_digest != activation.package_digest()
        || verified.generation != activation.generation()
        || !activation.is_dispatchable(generations)
    {
        return Err(PluginToolPublicationError::StaleActivation);
    }
    let mut registry = ToolRegistry::new();
    let snapshot = registry
        .register_batch_snapshot_exact(verified.definitions)
        .map_err(PluginToolPublicationError::Registry)?;
    Ok(ActivePluginToolset {
        activation_id: verified.activation_id,
        package_digest: verified.package_digest,
        generation: verified.generation,
        descriptor_snapshot_digest: verified.descriptor_snapshot_digest,
        registry,
        snapshot,
    })
}

include!("tools/digest.rs");
