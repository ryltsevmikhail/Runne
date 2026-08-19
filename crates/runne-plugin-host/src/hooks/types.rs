use sha2::{Digest, Sha256};

use crate::{
    PluginActivationId, PluginActivationSnapshot, PluginBootstrapFrame, PluginDigest,
    PluginGeneration, PluginGenerationPort, PluginHookId, PluginHookInvocationId,
    PluginTransportPort, PluginTransportPortError,
};
use runne_plugin_protocol::id::PluginId;

const HOOK_PAYLOAD_DIGEST_DOMAIN: &[u8] = b"RUNNE_PLUGIN_HOOK_PAYLOAD_V1\0";
const HOOK_REQUEST_DIGEST_DOMAIN: &[u8] = b"RUNNE_PLUGIN_HOOK_REQUEST_V1\0";
const HOOK_RESPONSE_BYTES: usize = 33;
/// Maximum retained bytes in one plugin hook payload.
pub const MAX_PLUGIN_HOOK_PAYLOAD_BYTES: usize = 1024 * 1024;
/// Maximum descriptors in one immutable hook dispatch set.
pub const MAX_PLUGIN_HOOK_DEFINITIONS: usize = 4096;

/// Trusted monotonic clock used only for deadline admission.
pub trait PluginHookClockPort {
    /// Returns the current trusted monotonic tick.
    fn now_tick(&self) -> u64;
}

/// Failure containment policy for one immutable hook descriptor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PluginHookFailurePolicy {
    /// Failure is recorded and isolated from the guarded operation.
    Optional,
    /// Failure closes the guarded operation as failed.
    Required,
    /// Any non-success closes the guarded operation as denied.
    Security,
}

/// Immutable hook descriptor used by a TaskRun-local descriptor snapshot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PluginHookDefinition {
    priority: i32,
    plugin_id: PluginId,
    hook_id: PluginHookId,
    failure_policy: PluginHookFailurePolicy,
}

impl PluginHookDefinition {
    /// Creates one bounded hook descriptor.
    pub const fn new(
        priority: i32,
        plugin_id: PluginId,
        hook_id: PluginHookId,
        failure_policy: PluginHookFailurePolicy,
    ) -> Self {
        Self {
            priority,
            plugin_id,
            hook_id,
            failure_policy,
        }
    }

    /// Ordered priority; lower values dispatch first.
    pub const fn priority(&self) -> i32 {
        self.priority
    }

    /// Package identity owning the hook.
    pub const fn plugin_id(&self) -> &PluginId {
        &self.plugin_id
    }

    /// Hook identity within the package.
    pub const fn hook_id(&self) -> &PluginHookId {
        &self.hook_id
    }
}

/// Complete authority-accepted hook descriptor set for one activation revision.
///
/// The contained definitions are intentionally not exposed: callers cannot
/// remove a required/security hook after the authority accepts the full set.
pub struct VerifiedPluginHookDescriptors {
    activation_id: PluginActivationId,
    package_digest: PluginDigest,
    generation: PluginGeneration,
    descriptor_snapshot_digest: [u8; 32],
    definitions: Box<[PluginHookDefinition]>,
}

impl VerifiedPluginHookDescriptors {
    /// Exact digest accepted for the complete descriptor set.
    pub const fn descriptor_snapshot_digest(&self) -> &[u8; 32] {
        &self.descriptor_snapshot_digest
    }

    /// Number of descriptors in the inseparable verified set.
    pub const fn len(&self) -> usize {
        self.definitions.len()
    }

    /// Whether the verified set contains no hooks.
    pub const fn is_empty(&self) -> bool {
        self.definitions.is_empty()
    }
}

/// Trusted authority that accepts the exact manifest/handshake descriptor digest.
pub trait PluginHookDescriptorAuthorityPort {
    /// Returns true only for a pinned descriptor snapshot bound to this activation.
    fn accepts(
        &self,
        activation: &PluginActivationSnapshot,
        descriptor_snapshot_digest: [u8; 32],
    ) -> bool;
}

/// Rejection while capturing immutable hook input.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PluginHookInvocationError {
    /// Payload exceeded the trusted hook bound.
    TooLarge,
    /// Supplied digest did not match the exact retained bytes.
    DigestMismatch,
    /// Deadline was not a non-zero monotonic tick.
    InvalidDeadline,
}

/// Immutable hook input bound to one invocation and trusted deadline.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PluginHookInvocation {
    invocation_id: PluginHookInvocationId,
    deadline_tick: u64,
    payload: Box<[u8]>,
    payload_digest: [u8; 32],
}

impl PluginHookInvocation {
    /// Captures bounded bytes and computes their exact digest.
    pub fn try_new(
        invocation_id: PluginHookInvocationId,
        deadline_tick: u64,
        payload: Vec<u8>,
    ) -> Result<Self, PluginHookInvocationError> {
        if deadline_tick == 0 {
            return Err(PluginHookInvocationError::InvalidDeadline);
        }
        if payload.len() > MAX_PLUGIN_HOOK_PAYLOAD_BYTES {
            return Err(PluginHookInvocationError::TooLarge);
        }
        let payload_digest = hook_payload_digest(&payload);
        Ok(Self {
            invocation_id,
            deadline_tick,
            payload: payload.into_boxed_slice(),
            payload_digest,
        })
    }

    /// Captures bytes only when the caller-supplied digest matches.
    pub fn try_new_with_digest(
        invocation_id: PluginHookInvocationId,
        deadline_tick: u64,
        payload: Vec<u8>,
        payload_digest: [u8; 32],
    ) -> Result<Self, PluginHookInvocationError> {
        let invocation = Self::try_new(invocation_id, deadline_tick, payload)?;
        if invocation.payload_digest != payload_digest {
            return Err(PluginHookInvocationError::DigestMismatch);
        }
        Ok(invocation)
    }

    /// Exact retained payload digest.
    pub const fn payload_digest(&self) -> &[u8; 32] {
        &self.payload_digest
    }

    pub(crate) const fn invocation_id(&self) -> &PluginHookInvocationId {
        &self.invocation_id
    }
}

/// Closed result of one hook dispatch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PluginHookDisposition {
    /// Plugin returned a bounded correlated successful result.
    Completed,
    /// Policy denied dispatch or the plugin denied the guarded operation.
    Denied,
    /// Dispatch provably did not cross the effect boundary or terminally failed.
    Failed,
    /// Dispatch may have crossed the plugin effect boundary without a result.
    Uncertain,
}

/// Ordered receipt for one dispatched or fail-closed hook.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PluginHookResult {
    definition: PluginHookDefinition,
    disposition: PluginHookDisposition,
}

impl PluginHookResult {
    /// Descriptor that produced this receipt.
    pub const fn definition(&self) -> &PluginHookDefinition {
        &self.definition
    }

    /// Closed hook disposition.
    pub const fn disposition(&self) -> PluginHookDisposition {
        self.disposition
    }
}

/// Complete deterministic dispatch result for one guarded operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PluginHookDispatch {
    results: Box<[PluginHookResult]>,
    guarded_operation_allowed: bool,
}

impl PluginHookDispatch {
    /// Results in canonical `(priority, plugin_id, hook_id)` order.
    pub fn results(&self) -> &[PluginHookResult] {
        &self.results
    }

    /// Whether all required/security policies permit the guarded operation.
    pub const fn guarded_operation_allowed(&self) -> bool {
        self.guarded_operation_allowed
    }
}

/// Whole-set rejection before any hook can reach the transport.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PluginHookDispatchError {
    /// Descriptor count exceeded the trusted immutable snapshot bound.
    TooManyDefinitions,
    /// A descriptor did not belong to the exact verified activation owner.
    OwnerMismatch,
    /// Same invocation/hook identity was replayed with different request bytes.
    IntentConflict,
    /// Durable dispatch authority was unavailable.
    AuthorityUnavailable,
    /// Hook definitions were not issued by a pinned descriptor authority.
    DescriptorUnverified,
}
