impl PluginActivationSnapshot {
    fn bounded_receipts(receipts: Vec<PluginActivationReceipt>) -> Box<[PluginActivationReceipt]> {
        assert!(receipts.len() <= MAX_ACTIVATION_RECEIPTS);
        receipts.into_boxed_slice()
    }

    fn pre_start(request: &PluginActivationRequest, state: ActivationState) -> Self {
        Self {
            plugin_id: request.package.plugin_hello_metadata().package_id,
            activation_id: request.activation_id.clone(),
            package_digest: request.package.package_digest(),
            generation: request.package.generation(),
            negotiation_snapshot: request.package.negotiation_snapshot(),
            state,
            start_intent: None,
            process_lease: None,
            drain_evidence: None,
            terminal_evidence: None,
            generation_lease: None,
            active_fence: None,
            history: vec![state].into_boxed_slice(),
            receipts: Self::bounded_receipts(Vec::new()),
        }
    }

    fn post_start(
        request: &PluginActivationRequest,
        state: ActivationState,
        start_intent: PluginStartIntent,
        process_lease: Option<PluginProcessLease>,
        generation_lease: PluginGenerationReadLease,
        active_fence: Option<PluginActiveFence>,
        receipts: Box<[PluginActivationReceipt]>,
    ) -> Self {
        Self {
            plugin_id: request.package.plugin_hello_metadata().package_id,
            activation_id: request.activation_id.clone(),
            package_digest: request.package.package_digest(),
            generation: request.package.generation(),
            negotiation_snapshot: request.package.negotiation_snapshot(),
            state,
            start_intent: Some(start_intent),
            process_lease,
            drain_evidence: None,
            terminal_evidence: None,
            generation_lease: Some(generation_lease),
            active_fence,
            history: Vec::new().into_boxed_slice(),
            receipts,
        }
    }

    fn started(request: &PluginActivationRequest, started: StartedActivation) -> Self {
        let mut snapshot = Self::post_start(
            request,
            started.state,
            started.start_intent,
            started.process_lease,
            started.generation_lease,
            started.active_fence,
            started.receipts,
        );
        let mut history = vec![ActivationState::Verified, ActivationState::Starting];
        if started.negotiated {
            history.push(ActivationState::Negotiating);
        }
        history.push(started.state);
        snapshot.history = history.into_boxed_slice();
        snapshot
    }

    pub fn activation_id(&self) -> &PluginActivationId {
        &self.activation_id
    }
    /// Exact verified package identity owning this activation channel.
    pub const fn plugin_id(&self) -> &PluginId {
        &self.plugin_id
    }
    pub const fn package_digest(&self) -> PluginDigest {
        self.package_digest
    }
    pub const fn generation(&self) -> PluginGeneration {
        self.generation
    }
    /// Returns the immutable registry-issued negotiation snapshot digest.
    pub const fn negotiation_snapshot(&self) -> ProtocolNegotiationSnapshotDigest {
        self.negotiation_snapshot
    }
    /// Returns the retained registry lease generation for crate-local evidence tests.
    #[cfg(test)]
    pub(crate) const fn retained_generation_lease_generation(&self) -> Option<PluginGeneration> {
        match &self.generation_lease {
            Some(lease) => Some(lease.generation()),
            None => None,
        }
    }
    pub const fn state(&self) -> ActivationState {
        self.state
    }
    /// Immutable committed lifecycle states, ending at [`Self::state`].
    pub fn transition_history(&self) -> &[ActivationState] {
        &self.history
    }

    /// Immutable bounded receipts for attempted process-boundary work.
    pub fn attempt_receipts(&self) -> &[PluginActivationReceipt] {
        &self.receipts
    }

    /// Revalidates the registry-owned active binding before hook/tool dispatch.
    pub fn is_dispatchable(&self, generations: &dyn PluginGenerationPort) -> bool {
        self.state == ActivationState::Active
            && self.active_fence.as_ref().is_some_and(|fence| {
                fence.matches(
                    &self.activation_id,
                    self.generation,
                    self.negotiation_snapshot,
                ) && generations.validate_active(fence).is_ok()
            })
    }


}
