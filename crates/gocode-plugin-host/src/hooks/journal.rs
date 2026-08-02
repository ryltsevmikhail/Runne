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
