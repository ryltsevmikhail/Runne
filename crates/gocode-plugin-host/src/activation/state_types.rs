/// Boundary work that was attempted but did not necessarily become a lifecycle state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PluginActivationReceipt {
    StartAttempted,
    StartProvenNotStarted,
    ReconciliationAttempted,
}

/// Linear lifecycle result. Active and uncertain snapshots retain the exact leases.
#[derive(Debug)]
pub struct PluginActivationSnapshot {
    plugin_id: PluginId,
    activation_id: PluginActivationId,
    package_digest: PluginDigest,
    generation: PluginGeneration,
    negotiation_snapshot: ProtocolNegotiationSnapshotDigest,
    state: ActivationState,
    start_intent: Option<PluginStartIntent>,
    process_lease: Option<PluginProcessLease>,
    drain_evidence: Option<PluginDrainEvidence>,
    terminal_evidence: Option<PluginTerminalEvidence>,
    generation_lease: Option<PluginGenerationReadLease>,
    active_fence: Option<PluginActiveFence>,
    history: Box<[ActivationState]>,
    receipts: Box<[PluginActivationReceipt]>,
}

struct StartedActivation {
    state: ActivationState,
    start_intent: PluginStartIntent,
    process_lease: Option<PluginProcessLease>,
    generation_lease: PluginGenerationReadLease,
    active_fence: Option<PluginActiveFence>,
    negotiated: bool,
    receipts: Box<[PluginActivationReceipt]>,
}
