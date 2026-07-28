//! Project-owned process and bootstrap transport ports for plugin activation.

use crate::{PluginActivationId, PluginDigest, PluginGeneration};
use gocode_plugin_protocol::digest::ProtocolNegotiationSnapshotDigest;

/// Durable origin of a plugin-start intent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PluginStartIntentOrigin {
    /// The journal row was created by this reservation call.
    Fresh,
    /// The exact journal row already existed and must be reconciled.
    Existing,
}

/// Opaque host-created reservation for one exact process start request.
#[derive(Debug, PartialEq, Eq)]
pub struct PluginStartIntent {
    activation_id: PluginActivationId,
    package_digest: PluginDigest,
    generation: PluginGeneration,
    reservation: [u8; 32],
    origin: PluginStartIntentOrigin,
}

impl PluginStartIntent {
    #[allow(dead_code)] // Called by an external durable authority implementation.
    pub(crate) fn issued(
        activation_id: PluginActivationId,
        package_digest: PluginDigest,
        generation: PluginGeneration,
        reservation: [u8; 32],
    ) -> Self {
        Self::with_origin(
            activation_id,
            package_digest,
            generation,
            reservation,
            PluginStartIntentOrigin::Fresh,
        )
    }

    pub(crate) fn with_origin(
        activation_id: PluginActivationId,
        package_digest: PluginDigest,
        generation: PluginGeneration,
        reservation: [u8; 32],
        origin: PluginStartIntentOrigin,
    ) -> Self {
        Self {
            activation_id,
            package_digest,
            generation,
            reservation,
            origin,
        }
    }

    pub(crate) fn matches(
        &self,
        activation_id: &PluginActivationId,
        package_digest: PluginDigest,
        generation: PluginGeneration,
    ) -> bool {
        self.activation_id == *activation_id
            && self.package_digest == package_digest
            && self.generation == generation
    }

    pub(crate) const fn reservation(&self) -> &[u8; 32] {
        &self.reservation
    }

    pub(crate) const fn origin(&self) -> PluginStartIntentOrigin {
        self.origin
    }
}

/// Failure to reserve a durable plugin-start intent before crossing the process boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PluginStartIntentPortError {
    /// The durable reservation service is unavailable.
    Unavailable,
    /// An existing durable reservation conflicts with this activation.
    Conflict,
}

/// Atomic durable journal failure for a plugin-start reservation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PluginStartIntentJournalError {
    /// The journal could not durably complete the operation.
    Unavailable,
    /// This activation id is already bound to different verified authority data.
    Conflict,
}

/// Durable reservation result. Existing reservations must be reconciled before
/// another start can be attempted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PluginStartIntentJournalResult {
    /// This call atomically created the durable row.
    Fresh([u8; 32]),
    /// This call recovered an exact previously persisted row.
    Existing([u8; 32]),
}

/// Immutable authority binding that must be recorded before process start.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PluginStartIntentBinding {
    activation_id: PluginActivationId,
    package_digest: PluginDigest,
    generation: PluginGeneration,
}

impl PluginStartIntentBinding {
    /// Creates the exact registry-verified binding for one activation.
    pub fn new(
        activation_id: PluginActivationId,
        package_digest: PluginDigest,
        generation: PluginGeneration,
    ) -> Self {
        Self {
            activation_id,
            package_digest,
            generation,
        }
    }

    /// Returns the activation correlation id.
    pub fn activation_id(&self) -> &PluginActivationId {
        &self.activation_id
    }
    /// Returns the verified package digest.
    pub const fn package_digest(&self) -> PluginDigest {
        self.package_digest
    }
    /// Returns the registry generation.
    pub const fn generation(&self) -> PluginGeneration {
        self.generation
    }
}

/// Project-owned durable storage boundary for atomic start-intent reservation.
///
/// Implementations must atomically insert this exact binding or return the
/// previously stored reservation for the same binding. A reused activation id
/// with different package or generation must return `Conflict` without
/// mutation. The reservation must be non-zero and unique for distinct bindings.
pub trait PluginStartIntentJournal {
    /// Atomically reserves or looks up one binding and its opaque journal token.
    fn reserve_or_lookup(
        &self,
        binding: &PluginStartIntentBinding,
    ) -> Result<PluginStartIntentJournalResult, PluginStartIntentJournalError>;
}

/// Generic durable start-intent authority backed by a project-owned journal.
#[derive(Debug)]
pub struct DurablePluginStartIntentAuthority<J> {
    journal: J,
}

impl<J> DurablePluginStartIntentAuthority<J> {
    /// Wraps the durable journal used to persist reservations across host restart.
    pub const fn new(journal: J) -> Self {
        Self { journal }
    }

    /// Returns the wrapped journal for integration-owned lifecycle management.
    pub const fn journal(&self) -> &J {
        &self.journal
    }
}

impl<J: PluginStartIntentJournal> PluginStartIntentPort for DurablePluginStartIntentAuthority<J> {
    fn reserve(
        &self,
        activation_id: &PluginActivationId,
        package_digest: PluginDigest,
        generation: PluginGeneration,
    ) -> Result<PluginStartIntent, PluginStartIntentPortError> {
        let binding =
            PluginStartIntentBinding::new(activation_id.clone(), package_digest, generation);
        let reservation =
            self.journal
                .reserve_or_lookup(&binding)
                .map_err(|error| match error {
                    PluginStartIntentJournalError::Unavailable => {
                        PluginStartIntentPortError::Unavailable
                    }
                    PluginStartIntentJournalError::Conflict => PluginStartIntentPortError::Conflict,
                })?;
        let (reservation, origin) = match reservation {
            PluginStartIntentJournalResult::Fresh(value) => (value, PluginStartIntentOrigin::Fresh),
            PluginStartIntentJournalResult::Existing(value) => {
                (value, PluginStartIntentOrigin::Existing)
            }
        };
        if reservation == [0; 32] {
            return Err(PluginStartIntentPortError::Unavailable);
        }
        Ok(PluginStartIntent::with_origin(
            activation_id.clone(),
            package_digest,
            generation,
            reservation,
            origin,
        ))
    }
}

/// Project-owned durable reservation authority. Implementations must persist
/// uniqueness across restart; this port deliberately does not expose a public
/// successful reservation constructor.
pub trait PluginStartIntentPort {
    /// Reserves one opaque, non-cloneable start intent bound to this activation.
    fn reserve(
        &self,
        activation_id: &PluginActivationId,
        package_digest: PluginDigest,
        generation: PluginGeneration,
    ) -> Result<PluginStartIntent, PluginStartIntentPortError>;
}

/// Bounded bootstrap frame supplied by a plugin transport implementation.
#[derive(Debug, PartialEq, Eq)]
pub struct PluginBootstrapFrame(Box<[u8]>);

impl PluginBootstrapFrame {
    /// Retains an outbound frame constructed by the host.
    pub(crate) fn outbound(bytes: Vec<u8>) -> Self {
        Self(bytes.into_boxed_slice())
    }

    /// Returns the immutable bytes for a certified external transport backend.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// Exact activation binding that a process backend must certify.
#[derive(Debug, PartialEq, Eq)]
pub struct PluginProcessLease {
    activation_id: PluginActivationId,
    package_digest: PluginDigest,
    generation: PluginGeneration,
    reservation: [u8; 32],
}

/// Opaque backend evidence that the exact process accepted a drain boundary.
#[derive(Debug, PartialEq, Eq)]
pub struct PluginDrainEvidence {
    activation_id: PluginActivationId,
    package_digest: PluginDigest,
    generation: PluginGeneration,
    reservation: [u8; 32],
}

/// Opaque backend evidence that cleanup closed containment for the exact
/// terminal process.
#[derive(Debug, PartialEq, Eq)]
pub struct PluginCleanupEvidence {
    activation_id: PluginActivationId,
    package_digest: PluginDigest,
    generation: PluginGeneration,
    reservation: [u8; 32],
}

/// Registry-owned generation read lease held across activation negotiation.
#[derive(Debug, PartialEq, Eq)]
pub struct PluginGenerationReadLease {
    activation_id: PluginActivationId,
    generation: PluginGeneration,
}

/// Registry-issued binding proving an activation became ready under one exact
/// generation and negotiation snapshot.
#[derive(Debug, PartialEq, Eq)]
pub struct PluginActiveFence {
    activation_id: PluginActivationId,
    generation: PluginGeneration,
    negotiation_snapshot: ProtocolNegotiationSnapshotDigest,
}

impl PluginActiveFence {
    pub(crate) fn issued(
        lease: &PluginGenerationReadLease,
        negotiation_snapshot: ProtocolNegotiationSnapshotDigest,
    ) -> Self {
        Self {
            activation_id: lease.activation_id.clone(),
            generation: lease.generation,
            negotiation_snapshot,
        }
    }

    pub(crate) fn matches(
        &self,
        activation_id: &PluginActivationId,
        generation: PluginGeneration,
        negotiation_snapshot: ProtocolNegotiationSnapshotDigest,
    ) -> bool {
        self.activation_id == *activation_id
            && self.generation == generation
            && self.negotiation_snapshot == negotiation_snapshot
    }

    pub(crate) fn activation_id(&self) -> &PluginActivationId {
        &self.activation_id
    }

    pub(crate) const fn generation(&self) -> PluginGeneration {
        self.generation
    }

    pub(crate) const fn negotiation_snapshot(&self) -> ProtocolNegotiationSnapshotDigest {
        self.negotiation_snapshot
    }
}

impl PluginGenerationReadLease {
    pub(crate) fn issued(activation_id: PluginActivationId, generation: PluginGeneration) -> Self {
        Self {
            activation_id,
            generation,
        }
    }

    pub(crate) fn matches(
        &self,
        activation_id: &PluginActivationId,
        generation: PluginGeneration,
    ) -> bool {
        self.activation_id == *activation_id && self.generation == generation
    }

    pub(crate) fn activation_id(&self) -> &PluginActivationId {
        &self.activation_id
    }

    pub(crate) const fn generation(&self) -> PluginGeneration {
        self.generation
    }
}

impl PluginProcessLease {
    /// Creates evidence emitted only by a certified process backend.
    #[cfg(test)]
    pub(crate) fn certified(intent: &PluginStartIntent) -> Self {
        Self {
            activation_id: intent.activation_id.clone(),
            package_digest: intent.package_digest,
            generation: intent.generation,
            reservation: *intent.reservation(),
        }
    }

    pub(crate) fn matches(&self, intent: &PluginStartIntent) -> bool {
        self.activation_id == intent.activation_id
            && self.package_digest == intent.package_digest
            && self.generation == intent.generation
            && self.reservation == *intent.reservation()
    }

    #[cfg(test)]
    pub(crate) fn activation_id(&self) -> &PluginActivationId {
        &self.activation_id
    }

    #[cfg(test)]
    pub(crate) const fn package_digest(&self) -> PluginDigest {
        self.package_digest
    }

    #[cfg(test)]
    pub(crate) const fn generation(&self) -> PluginGeneration {
        self.generation
    }

    #[cfg(test)]
    pub(crate) const fn reservation(&self) -> &[u8; 32] {
        &self.reservation
    }
}

impl PluginDrainEvidence {
    #[cfg(test)]
    pub(crate) fn certified(lease: &PluginProcessLease) -> Self {
        Self {
            activation_id: lease.activation_id.clone(),
            package_digest: lease.package_digest,
            generation: lease.generation,
            reservation: lease.reservation,
        }
    }

    pub(crate) fn matches(&self, lease: &PluginProcessLease) -> bool {
        self.activation_id == lease.activation_id
            && self.package_digest == lease.package_digest
            && self.generation == lease.generation
            && self.reservation == lease.reservation
    }
}

impl PluginCleanupEvidence {
    #[cfg(test)]
    pub(crate) fn certified(lease: &PluginProcessLease) -> Self {
        Self {
            activation_id: lease.activation_id.clone(),
            package_digest: lease.package_digest,
            generation: lease.generation,
            reservation: lease.reservation,
        }
    }

    pub(crate) fn matches(&self, lease: &PluginProcessLease) -> bool {
        self.activation_id == lease.activation_id
            && self.package_digest == lease.package_digest
            && self.generation == lease.generation
            && self.reservation == lease.reservation
    }
}

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

#[cfg(test)]
mod tests {
    use std::{
        collections::HashMap,
        sync::{
            Arc, Barrier, Mutex,
            atomic::{AtomicUsize, Ordering},
        },
    };

    use super::*;

    #[derive(Clone, Default)]
    struct MemoryJournal(Arc<Mutex<MemoryJournalState>>);

    #[derive(Default)]
    struct MemoryJournalState {
        entries: HashMap<PluginActivationId, (PluginStartIntentBinding, [u8; 32])>,
        next: u64,
    }

    impl MemoryJournal {
        fn row_count(&self) -> usize {
            self.0.lock().unwrap().entries.len()
        }

        fn allocation_count(&self) -> u64 {
            self.0.lock().unwrap().next
        }
    }

    impl PluginStartIntentJournal for MemoryJournal {
        fn reserve_or_lookup(
            &self,
            binding: &PluginStartIntentBinding,
        ) -> Result<PluginStartIntentJournalResult, PluginStartIntentJournalError> {
            let mut state = self.0.lock().unwrap();
            if let Some((stored, reservation)) = state.entries.get(binding.activation_id()) {
                return if stored == binding {
                    Ok(PluginStartIntentJournalResult::Existing(*reservation))
                } else {
                    Err(PluginStartIntentJournalError::Conflict)
                };
            }
            state.next += 1;
            let mut reservation = [0; 32];
            reservation[..8].copy_from_slice(&state.next.to_be_bytes());
            state.entries.insert(
                binding.activation_id().clone(),
                (binding.clone(), reservation),
            );
            Ok(PluginStartIntentJournalResult::Fresh(reservation))
        }
    }

    #[derive(Clone)]
    struct RaceJournal {
        journal: MemoryJournal,
        entered: Arc<AtomicUsize>,
        entrants_before_first_mutation: Arc<AtomicUsize>,
        barrier: Arc<Barrier>,
    }

    impl RaceJournal {
        fn new() -> Self {
            Self {
                journal: MemoryJournal::default(),
                entered: Arc::new(AtomicUsize::new(0)),
                entrants_before_first_mutation: Arc::new(AtomicUsize::new(0)),
                barrier: Arc::new(Barrier::new(2)),
            }
        }

        fn entered_calls(&self) -> usize {
            self.entered.load(Ordering::SeqCst)
        }

        fn row_count(&self) -> usize {
            self.journal.row_count()
        }

        fn allocation_count(&self) -> u64 {
            self.journal.allocation_count()
        }

        fn entrants_before_first_mutation(&self) -> usize {
            self.entrants_before_first_mutation.load(Ordering::SeqCst)
        }
    }

    impl PluginStartIntentJournal for RaceJournal {
        fn reserve_or_lookup(
            &self,
            binding: &PluginStartIntentBinding,
        ) -> Result<PluginStartIntentJournalResult, PluginStartIntentJournalError> {
            let entrant = self.entered.fetch_add(1, Ordering::SeqCst);
            if entrant < 2 {
                self.barrier.wait();
            }
            let entrants = self.entered.load(Ordering::SeqCst);
            let _ = self.entrants_before_first_mutation.compare_exchange(
                0,
                entrants,
                Ordering::SeqCst,
                Ordering::SeqCst,
            );
            self.journal.reserve_or_lookup(binding)
        }
    }

    #[test]
    fn durable_authority_replays_exact_binding_across_restart_but_rejects_stale_binding() {
        let journal = MemoryJournal::default();
        let activation = PluginActivationId::new("durable-activation").unwrap();
        let digest = PluginDigest::from_bytes([1; 32]);
        let first = DurablePluginStartIntentAuthority::new(journal.clone())
            .reserve(&activation, digest, PluginGeneration::INITIAL)
            .unwrap();
        let replay = DurablePluginStartIntentAuthority::new(journal.clone())
            .reserve(&activation, digest, PluginGeneration::INITIAL)
            .unwrap();
        assert_eq!(first.reservation(), replay.reservation());
        assert_eq!(first.origin(), PluginStartIntentOrigin::Fresh);
        assert_eq!(replay.origin(), PluginStartIntentOrigin::Existing);

        let different = DurablePluginStartIntentAuthority::new(journal).reserve(
            &activation,
            digest,
            PluginGeneration::new(2).unwrap(),
        );
        assert_eq!(different, Err(PluginStartIntentPortError::Conflict));
    }

    #[test]
    fn durable_authority_never_reuses_a_reservation_for_distinct_activation() {
        let journal = MemoryJournal::default();
        let authority = DurablePluginStartIntentAuthority::new(journal);
        let digest = PluginDigest::from_bytes([1; 32]);
        let first = authority
            .reserve(
                &PluginActivationId::new("first").unwrap(),
                digest,
                PluginGeneration::INITIAL,
            )
            .unwrap();
        let second = authority
            .reserve(
                &PluginActivationId::new("second").unwrap(),
                digest,
                PluginGeneration::INITIAL,
            )
            .unwrap();
        assert_ne!(first.reservation(), second.reservation());
    }

    #[test]
    fn durable_authority_restart_replays_and_distinct_activation_gets_a_new_journal_row() {
        let journal = MemoryJournal::default();
        let digest = PluginDigest::from_bytes([3; 32]);
        let first_id = PluginActivationId::new("restart-first").unwrap();
        let first = DurablePluginStartIntentAuthority::new(journal.clone())
            .reserve(&first_id, digest, PluginGeneration::INITIAL)
            .unwrap();
        let reconstructed = DurablePluginStartIntentAuthority::new(journal.clone());
        let replay = reconstructed
            .reserve(&first_id, digest, PluginGeneration::INITIAL)
            .unwrap();
        let distinct = reconstructed
            .reserve(
                &PluginActivationId::new("restart-distinct").unwrap(),
                digest,
                PluginGeneration::INITIAL,
            )
            .unwrap();

        assert_eq!(first.reservation(), replay.reservation());
        assert_eq!(first.origin(), PluginStartIntentOrigin::Fresh);
        assert_eq!(replay.origin(), PluginStartIntentOrigin::Existing);
        assert_ne!(first.reservation(), distinct.reservation());
        assert_eq!(journal.row_count(), 2);
    }

    #[test]
    fn durable_authority_two_thread_reserve_race_creates_one_row_and_stable_token() {
        let journal = RaceJournal::new();
        let left_authority =
            std::sync::Arc::new(DurablePluginStartIntentAuthority::new(journal.clone()));
        let right_authority =
            std::sync::Arc::new(DurablePluginStartIntentAuthority::new(journal.clone()));
        let activation = PluginActivationId::new("reserve-race").unwrap();
        let digest = PluginDigest::from_bytes([4; 32]);
        let left = {
            let authority = left_authority.clone();
            let activation = activation.clone();
            std::thread::spawn(move || {
                authority
                    .reserve(&activation, digest, PluginGeneration::INITIAL)
                    .unwrap()
            })
        };
        let right = {
            let authority = right_authority.clone();
            let activation = activation.clone();
            std::thread::spawn(move || {
                authority
                    .reserve(&activation, digest, PluginGeneration::INITIAL)
                    .unwrap()
            })
        };
        let left = left.join().unwrap();
        let right = right.join().unwrap();

        assert_eq!(left.reservation(), right.reservation());
        assert_eq!(journal.entered_calls(), 2);
        assert_eq!(journal.entrants_before_first_mutation(), 2);
        let replay = DurablePluginStartIntentAuthority::new(journal.clone())
            .reserve(&activation, digest, PluginGeneration::INITIAL)
            .unwrap();
        assert_eq!(left.reservation(), replay.reservation());
        assert_eq!(journal.entered_calls(), 3);
        assert_eq!(journal.row_count(), 1);
        assert_eq!(journal.allocation_count(), 1);
    }
}
