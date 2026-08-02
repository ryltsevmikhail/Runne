/// Failure to start a plugin through the project process boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PluginProcessPortError {
    /// The native certified containment backend is unavailable.
    BackendUnavailable,
    /// The broker rejected the requested process start.
    Rejected,
    /// The start request may have reached the backend but its response was lost.
    ResponseLost,
}

/// Result of reconciling an existing durable start reservation.
#[derive(Debug, PartialEq, Eq)]
pub enum PluginStartReconciliation {
    /// Certified backend proves no process was started for the reservation.
    NotStarted,
    /// Certified backend proves the exact process is already running.
    Started(PluginProcessLease),
    /// Backend cannot prove either state; caller must retain reconciliation state.
    Uncertain,
}

/// Registry lookup failure for an activation generation fence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PluginGenerationPortError {
    /// The authoritative activation generation is unavailable.
    Unavailable,
}

/// Registry-owned source of the current activation generation.
pub trait PluginGenerationPort {
    /// Acquires a registry-owned read lease for the one current generation.
    fn acquire_read_lease(
        &self,
        activation_id: &PluginActivationId,
    ) -> Result<PluginGenerationReadLease, PluginGenerationPortError>;

    /// Performs the ready-CAS immediately before an activation becomes active.
    fn ready_compare_and_set(
        &self,
        lease: &PluginGenerationReadLease,
    ) -> Result<(), PluginGenerationPortError>;

    /// Atomically publishes the exact ready binding after the generation CAS.
    fn publish_active(
        &self,
        lease: &PluginGenerationReadLease,
        negotiation_snapshot: ProtocolNegotiationSnapshotDigest,
    ) -> Result<PluginActiveFence, PluginGenerationPortError> {
        self.ready_compare_and_set(lease)?;
        Ok(PluginActiveFence::issued(lease, negotiation_snapshot))
    }

    /// Revalidates an active binding before dispatch. Implementations must fail
    /// closed when the registry epoch or negotiation snapshot changed.
    fn validate_active(&self, _: &PluginActiveFence) -> Result<(), PluginGenerationPortError> {
        Err(PluginGenerationPortError::Unavailable)
    }
}

/// Project-owned process activation port; it exposes no OS process handles.
pub trait PluginProcessPort {
    /// Starts the exact verified package and returns certified containment evidence.
    fn start(
        &mut self,
        intent: &PluginStartIntent,
        generation_lease: &PluginGenerationReadLease,
    ) -> Result<PluginProcessLease, PluginProcessPortError>;

    /// Reconciles a recovered durable reservation before any repeat start.
    fn reconcile(
        &mut self,
        _: &PluginStartIntent,
        _: &PluginGenerationReadLease,
    ) -> Result<PluginStartReconciliation, PluginProcessPortError> {
        Err(PluginProcessPortError::ResponseLost)
    }

    /// Requests certified draining for an active process. Exact duplicate calls
    /// for the same lease must be idempotent and return the same evidence.
    fn begin_draining(
        &mut self,
        _: &PluginProcessLease,
    ) -> Result<PluginDrainEvidence, PluginProcessPortError> {
        Err(PluginProcessPortError::BackendUnavailable)
    }

    /// Requests certified terminal reconciliation for a draining process.
    /// Exact duplicate calls for the same lease/evidence must be idempotent.
    fn terminal(
        &mut self,
        _: &PluginProcessLease,
        _: &PluginDrainEvidence,
    ) -> Result<crate::PluginTerminalEvidence, PluginProcessPortError> {
        Err(PluginProcessPortError::BackendUnavailable)
    }

    /// Closes containment and cleanup only after exact terminal evidence.
    /// Exact duplicate calls must be idempotent and return the same evidence.
    fn cleanup(
        &mut self,
        _: &PluginProcessLease,
        _: &crate::PluginTerminalEvidence,
    ) -> Result<PluginCleanupEvidence, PluginProcessPortError> {
        Err(PluginProcessPortError::BackendUnavailable)
    }
}

/// Failure reported by the bounded plugin bootstrap transport.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PluginTransportPortError {
    /// Transport proved that no outbound bytes were accepted.
    NotSent,
    /// The transport could not produce a response frame.
    Unavailable,
    /// Outbound bytes may have crossed the effect boundary but no response is known.
    ResponseLost,
    /// Trusted deadline elapsed after dispatch may have crossed the effect boundary.
    DeadlineExceeded,
}

/// Project-owned bootstrap transport port; it exposes no raw OS handles.
pub trait PluginTransportPort {
    /// Sends one bounded host-owned frame.
    fn send(&mut self, outbound: PluginBootstrapFrame) -> Result<(), PluginTransportPortError>;

    /// Sends one frame under a trusted monotonic deadline.
    ///
    /// Implementations that cannot prove deadline enforcement fail closed and
    /// are ineligible for hook dispatch.
    fn send_before(
        &mut self,
        _: u64,
        _: PluginBootstrapFrame,
    ) -> Result<(), PluginTransportPortError> {
        Err(PluginTransportPortError::NotSent)
    }

    /// Receives one response into the host-owned bounded buffer.
    fn receive(&mut self, inbound: &mut [u8]) -> Result<usize, PluginTransportPortError>;

    /// Receives one response under a trusted monotonic deadline.
    ///
    /// Implementations that cannot enforce the deadline fail closed and are
    /// ineligible for hook dispatch.
    fn receive_before(&mut self, _: u64, _: &mut [u8]) -> Result<usize, PluginTransportPortError> {
        Err(PluginTransportPortError::Unavailable)
    }
}
