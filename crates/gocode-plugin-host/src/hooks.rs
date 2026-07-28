//! Deterministic, fail-closed plugin hook dispatch.

use sha2::{Digest, Sha256};

use crate::{
    PluginActivationId, PluginActivationSnapshot, PluginBootstrapFrame, PluginDigest,
    PluginGeneration, PluginGenerationPort, PluginHookId, PluginHookInvocationId,
    PluginTransportPort, PluginTransportPortError,
};
use gocode_plugin_protocol::id::PluginId;

const HOOK_PAYLOAD_DIGEST_DOMAIN: &[u8] = b"GOCODE_PLUGIN_HOOK_PAYLOAD_V1\0";
const HOOK_REQUEST_DIGEST_DOMAIN: &[u8] = b"GOCODE_PLUGIN_HOOK_REQUEST_V1\0";
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

/// Verifies and binds a complete hook descriptor set to one active activation.
pub fn verify_plugin_hook_descriptors(
    definitions: &[PluginHookDefinition],
    activation: &PluginActivationSnapshot,
    generations: &dyn PluginGenerationPort,
    authority: &dyn PluginHookDescriptorAuthorityPort,
) -> Result<VerifiedPluginHookDescriptors, PluginHookDispatchError> {
    if !activation.is_dispatchable(generations) {
        return Err(PluginHookDispatchError::AuthorityUnavailable);
    }
    let ordered = Vec::from(ordered_plugin_hooks(definitions)?);
    if ordered
        .iter()
        .any(|definition| definition.plugin_id != *activation.plugin_id())
    {
        return Err(PluginHookDispatchError::OwnerMismatch);
    }
    let descriptor_digest = hook_descriptor_digest(&ordered);
    if !authority.accepts(activation, descriptor_digest) {
        return Err(PluginHookDispatchError::DescriptorUnverified);
    }
    Ok(VerifiedPluginHookDescriptors {
        activation_id: activation.activation_id().clone(),
        package_digest: activation.package_digest(),
        generation: activation.generation(),
        descriptor_snapshot_digest: descriptor_digest,
        definitions: ordered.into_boxed_slice(),
    })
}

/// Durable claim result for one exact hook request.
#[derive(Debug)]
pub enum PluginHookDispatchClaimResult {
    /// This caller owns the only permitted host send.
    Fresh(PluginHookDispatchClaim),
    /// Exact replay observes the prior closed outcome without another send.
    Existing(PluginHookDisposition),
}

/// Stable repository key for one hook dispatch intent.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct PluginHookDispatchJournalKey {
    activation_id: PluginActivationId,
    generation: PluginGeneration,
    invocation_id: PluginHookInvocationId,
    plugin_id: PluginId,
    hook_id: PluginHookId,
}

impl PluginHookDispatchJournalKey {
    /// Activation identity that owned the dispatch.
    pub const fn activation_id(&self) -> &PluginActivationId {
        &self.activation_id
    }

    /// Exact activation generation that owned the dispatch.
    pub const fn generation(&self) -> PluginGeneration {
        self.generation
    }

    /// Invocation identity shared by all hooks in one guarded operation.
    pub const fn invocation_id(&self) -> &PluginHookInvocationId {
        &self.invocation_id
    }

    /// Plugin package identity owning the hook.
    pub const fn plugin_id(&self) -> &PluginId {
        &self.plugin_id
    }

    /// Exact hook identity within the invocation.
    pub const fn hook_id(&self) -> &PluginHookId {
        &self.hook_id
    }
}

/// Atomic repository response for one exact hook intent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PluginHookDispatchJournalResult {
    /// The repository inserted a new open intent for this request.
    Fresh,
    /// The repository already contained this stable identity.
    Existing {
        /// Digest bound to the stored intent.
        request_digest: [u8; 32],
        /// Closed outcome, or `None` while delivery remains indeterminate.
        outcome: Option<PluginHookDisposition>,
    },
}

/// Opaque durable-store proof that an open dispatch owner was fenced dead.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PluginHookRecoveredDispatch {
    key: PluginHookDispatchJournalKey,
    request_digest: [u8; 32],
    recovery_token: [u8; 32],
}

impl PluginHookRecoveredDispatch {
    /// Creates a store-issued recovery proof.
    ///
    /// Implementations issue this only after atomically fencing the prior
    /// owner epoch. The same store validates the token during quarantine.
    pub const fn new(
        key: PluginHookDispatchJournalKey,
        request_digest: [u8; 32],
        recovery_token: [u8; 32],
    ) -> Self {
        Self {
            key,
            request_digest,
            recovery_token,
        }
    }

    /// Stable journal identity whose prior owner was fenced.
    pub const fn key(&self) -> &PluginHookDispatchJournalKey {
        &self.key
    }

    /// Exact request digest stored with the open intent.
    pub const fn request_digest(&self) -> &[u8; 32] {
        &self.request_digest
    }

    /// Store-owned token validated atomically during quarantine.
    pub const fn recovery_token(&self) -> &[u8; 32] {
        &self.recovery_token
    }
}

/// Durable hook journal failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PluginHookDispatchJournalError {
    /// Durable storage could not atomically read or mutate the record.
    Unavailable,
    /// Stable identity or request digest conflicts with the durable record.
    Conflict,
}

/// Repository-owned persistence boundary for exactly-once hook delivery.
pub trait PluginHookDispatchJournal: Send + Sync {
    /// Atomically inserts an open intent or returns the existing record.
    fn claim_or_lookup(
        &self,
        key: &PluginHookDispatchJournalKey,
        request_digest: [u8; 32],
    ) -> Result<PluginHookDispatchJournalResult, PluginHookDispatchJournalError>;

    /// Atomically closes an exact open intent with its final disposition.
    fn complete(
        &self,
        key: &PluginHookDispatchJournalKey,
        request_digest: [u8; 32],
        disposition: PluginHookDisposition,
    ) -> Result<(), PluginHookDispatchJournalError>;

    /// Returns whether any intent remains open and can block generation cutover.
    fn has_open_dispatches(&self) -> Result<bool, PluginHookDispatchJournalError>;

    /// Returns one recovery token only after fencing its prior owner epoch.
    fn next_recovered_dispatch(
        &self,
    ) -> Result<Option<PluginHookRecoveredDispatch>, PluginHookDispatchJournalError>;

    /// Atomically validates a recovery token and quarantines the dead-owner
    /// record as `Uncertain`.
    fn quarantine_recovered(
        &self,
        recovered: &PluginHookRecoveredDispatch,
    ) -> Result<(), PluginHookDispatchJournalError>;
}

/// Opaque single-use claim held from durable intent through closed outcome.
#[derive(Debug)]
pub struct PluginHookDispatchClaim {
    key: PluginHookDispatchJournalKey,
    request_digest: [u8; 32],
}

impl PluginHookDispatchClaim {
    pub(crate) fn new(
        activation: &PluginActivationSnapshot,
        plugin_id: PluginId,
        invocation_id: PluginHookInvocationId,
        hook_id: PluginHookId,
        request_digest: [u8; 32],
    ) -> Self {
        Self {
            key: PluginHookDispatchJournalKey {
                activation_id: activation.activation_id().clone(),
                generation: activation.generation(),
                invocation_id,
                plugin_id,
                hook_id,
            },
            request_digest,
        }
    }

    pub(crate) const fn key(&self) -> &PluginHookDispatchJournalKey {
        &self.key
    }

    pub(crate) const fn request_digest(&self) -> &[u8; 32] {
        &self.request_digest
    }
}

/// Durable exactly-once authority for hook intents and outcomes.
pub trait PluginHookDispatchAuthorityPort {
    /// Atomically validates the active binding and claims an exact request.
    fn claim(
        &self,
        activation: &PluginActivationSnapshot,
        definition: &PluginHookDefinition,
        invocation: &PluginHookInvocation,
        request_digest: [u8; 32],
    ) -> Result<PluginHookDispatchClaimResult, PluginHookDispatchError>;

    /// Durably closes a fresh claim before its outcome reaches the caller.
    fn complete(
        &self,
        claim: PluginHookDispatchClaim,
        disposition: PluginHookDisposition,
    ) -> Result<(), PluginHookDispatchError>;

    /// Quarantines one recovered open intent as `Uncertain` without plugin IPC.
    ///
    /// Stronger dispositions require a separate typed evidence boundary and
    /// cannot be forged through crash recovery.
    fn quarantine_recovered(
        &self,
        recovered: &PluginHookRecoveredDispatch,
    ) -> Result<(), PluginHookDispatchError>;
}

/// Freezes a global descriptor list in canonical
/// `(priority, plugin_id, hook_id)` order before per-activation routing.
pub fn ordered_plugin_hooks(
    definitions: &[PluginHookDefinition],
) -> Result<Box<[PluginHookDefinition]>, PluginHookDispatchError> {
    if definitions.len() > MAX_PLUGIN_HOOK_DEFINITIONS {
        return Err(PluginHookDispatchError::TooManyDefinitions);
    }
    let mut ordered = definitions.to_vec();
    ordered.sort_by(compare_hooks);
    Ok(ordered.into_boxed_slice())
}

/// Dispatches one activation-owned frozen descriptor set through the plugin
/// transport. Multi-plugin orchestration calls this boundary once per exact
/// activation after sorting the global descriptor snapshot.
pub fn dispatch_hooks(
    descriptors: &VerifiedPluginHookDescriptors,
    invocation: &PluginHookInvocation,
    activation: &PluginActivationSnapshot,
    generations: &dyn PluginGenerationPort,
    dispatches: &dyn PluginHookDispatchAuthorityPort,
    clock: &dyn PluginHookClockPort,
    transport: &mut dyn PluginTransportPort,
) -> Result<PluginHookDispatch, PluginHookDispatchError> {
    if descriptors.activation_id != *activation.activation_id()
        || descriptors.package_digest != activation.package_digest()
        || descriptors.generation != activation.generation()
    {
        return Err(PluginHookDispatchError::DescriptorUnverified);
    }

    let mut allowed = true;
    let mut channel_uncertain = false;
    let mut results = Vec::with_capacity(descriptors.definitions.len());
    for definition in descriptors.definitions.iter().cloned() {
        let current = clock.now_tick();
        let dispatchable = activation.is_dispatchable(generations);
        let disposition = if channel_uncertain || !dispatchable {
            PluginHookDisposition::Denied
        } else if current >= invocation.deadline_tick {
            PluginHookDisposition::Failed
        } else {
            dispatch_one(
                &definition,
                descriptors.descriptor_snapshot_digest,
                invocation,
                activation,
                dispatches,
                transport,
            )?
        };
        if disposition == PluginHookDisposition::Uncertain {
            channel_uncertain = true;
        }
        if definition.failure_policy != PluginHookFailurePolicy::Optional
            && disposition != PluginHookDisposition::Completed
        {
            allowed = false;
        }
        results.push(PluginHookResult {
            definition,
            disposition,
        });
    }
    Ok(PluginHookDispatch {
        results: results.into_boxed_slice(),
        guarded_operation_allowed: allowed,
    })
}

fn compare_hooks(left: &PluginHookDefinition, right: &PluginHookDefinition) -> core::cmp::Ordering {
    (
        left.priority,
        left.plugin_id.as_str(),
        left.hook_id.as_str(),
    )
        .cmp(&(
            right.priority,
            right.plugin_id.as_str(),
            right.hook_id.as_str(),
        ))
}

fn dispatch_one(
    definition: &PluginHookDefinition,
    descriptor_snapshot_digest: [u8; 32],
    invocation: &PluginHookInvocation,
    activation: &PluginActivationSnapshot,
    dispatches: &dyn PluginHookDispatchAuthorityPort,
    transport: &mut dyn PluginTransportPort,
) -> Result<PluginHookDisposition, PluginHookDispatchError> {
    let (outbound, request_digest) = encode_hook_request(
        definition,
        descriptor_snapshot_digest,
        invocation,
        activation,
    );
    let claim = match dispatches.claim(activation, definition, invocation, request_digest)? {
        PluginHookDispatchClaimResult::Fresh(claim) => claim,
        PluginHookDispatchClaimResult::Existing(disposition) => return Ok(disposition),
    };
    match transport.send_before(
        invocation.deadline_tick,
        PluginBootstrapFrame::outbound(outbound),
    ) {
        Ok(()) => {}
        Err(PluginTransportPortError::NotSent) => {
            dispatches.complete(claim, PluginHookDisposition::Failed)?;
            return Ok(PluginHookDisposition::Failed);
        }
        Err(
            PluginTransportPortError::Unavailable
            | PluginTransportPortError::ResponseLost
            | PluginTransportPortError::DeadlineExceeded,
        ) => {
            dispatches.complete(claim, PluginHookDisposition::Uncertain)?;
            return Ok(PluginHookDisposition::Uncertain);
        }
    };
    let mut response = [0u8; HOOK_RESPONSE_BYTES];
    let received = match transport.receive_before(invocation.deadline_tick, &mut response) {
        Ok(received) if received == HOOK_RESPONSE_BYTES => received,
        Ok(_) | Err(_) => {
            dispatches.complete(claim, PluginHookDisposition::Uncertain)?;
            return Ok(PluginHookDisposition::Uncertain);
        }
    };
    let disposition = if response[..32] != request_digest {
        PluginHookDisposition::Uncertain
    } else {
        match response[received - 1] {
            0 => PluginHookDisposition::Completed,
            1 => PluginHookDisposition::Denied,
            2 => PluginHookDisposition::Failed,
            3 => PluginHookDisposition::Uncertain,
            _ => PluginHookDisposition::Uncertain,
        }
    };
    dispatches.complete(claim, disposition)?;
    Ok(disposition)
}

fn encode_hook_request(
    definition: &PluginHookDefinition,
    descriptor_snapshot_digest: [u8; 32],
    invocation: &PluginHookInvocation,
    activation: &PluginActivationSnapshot,
) -> (Vec<u8>, [u8; 32]) {
    let mut encoded = Vec::with_capacity(256 + invocation.payload.len());
    encode_text(&mut encoded, invocation.invocation_id.as_str());
    encode_text(&mut encoded, activation.activation_id().as_str());
    encoded.extend_from_slice(&activation.generation().get().to_be_bytes());
    encoded.extend_from_slice(activation.negotiation_snapshot().as_bytes());
    encode_text(&mut encoded, definition.plugin_id.as_str());
    encode_text(&mut encoded, definition.hook_id.as_str());
    encoded.extend_from_slice(&descriptor_snapshot_digest);
    encoded.extend_from_slice(&invocation.deadline_tick.to_be_bytes());
    encoded.extend_from_slice(invocation.payload_digest());
    encoded.extend_from_slice(&(invocation.payload.len() as u64).to_be_bytes());
    encoded.extend_from_slice(&invocation.payload);
    let request_digest = request_digest(&encoded);
    encoded.extend_from_slice(&request_digest);
    (encoded, request_digest)
}

fn encode_text(encoded: &mut Vec<u8>, value: &str) {
    encoded.extend_from_slice(&(value.len() as u16).to_be_bytes());
    encoded.extend_from_slice(value.as_bytes());
}

fn hook_payload_digest(payload: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(HOOK_PAYLOAD_DIGEST_DOMAIN);
    hasher.update((payload.len() as u64).to_be_bytes());
    hasher.update(payload);
    hasher.finalize().into()
}

fn hook_descriptor_digest(definitions: &[PluginHookDefinition]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"GOCODE_PLUGIN_HOOK_DESCRIPTOR_SNAPSHOT_V1\0");
    hasher.update((definitions.len() as u64).to_be_bytes());
    for definition in definitions {
        hasher.update(definition.priority.to_be_bytes());
        hasher.update((definition.plugin_id.as_str().len() as u64).to_be_bytes());
        hasher.update(definition.plugin_id.as_str().as_bytes());
        hasher.update((definition.hook_id.as_str().len() as u64).to_be_bytes());
        hasher.update(definition.hook_id.as_str().as_bytes());
        hasher.update([match definition.failure_policy {
            PluginHookFailurePolicy::Optional => 0,
            PluginHookFailurePolicy::Required => 1,
            PluginHookFailurePolicy::Security => 2,
        }]);
    }
    hasher.finalize().into()
}

fn request_digest(request: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(HOOK_REQUEST_DIGEST_DOMAIN);
    hasher.update((request.len() as u64).to_be_bytes());
    hasher.update(request);
    hasher.finalize().into()
}
