//! Fail-closed plugin activation and exact bootstrap profile negotiation.
#![allow(missing_docs)]

use gocode_plugin_protocol::bootstrap::{
    BootstrapMessage, HostHello, PluginHello, ProfileSelected,
};
use gocode_plugin_protocol::bootstrap_v2::SelectionAcknowledgedV2;
use gocode_plugin_protocol::digest::{
    DigestAlgorithm, PackageDigest, ProtocolNegotiationSnapshotDigest,
};
use gocode_plugin_protocol::frame::{FrameLimits, decode_codec_frame, decode_frame, encode_frame};
use gocode_plugin_protocol::id::{Nonce, ProtocolSessionId};
use gocode_plugin_protocol::profile::DecodeLimits;

use crate::{
    PluginActivationId, PluginBootstrapFrame, PluginDigest, PluginGeneration, PluginGenerationPort,
    PluginGenerationReadLease, PluginProcessLease, PluginProcessPort, PluginProcessPortError,
    PluginStartIntent, PluginStartIntentPort, PluginTransportPort, VerifiedPluginPackage,
};

const MAX_BOOTSTRAP_FRAME_BYTES: usize = 64 * 1024;
const MAX_ACTIVATION_RECEIPTS: usize = 16;

/// Ordered lifecycle states for one plugin activation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActivationState {
    Verified,
    Starting,
    Negotiating,
    Active,
    Draining,
    Terminal,
    Uncertain,
}

/// Boundary work that was attempted but did not necessarily become a lifecycle state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PluginActivationReceipt {
    StartAttempted,
    StartProvenNotStarted,
}

/// Linear lifecycle result. Active and uncertain snapshots retain the exact leases.
#[derive(Debug)]
pub struct PluginActivationSnapshot {
    activation_id: PluginActivationId,
    package_digest: PluginDigest,
    generation: PluginGeneration,
    negotiation_snapshot: ProtocolNegotiationSnapshotDigest,
    state: ActivationState,
    start_intent: Option<PluginStartIntent>,
    process_lease: Option<PluginProcessLease>,
    generation_lease: Option<PluginGenerationReadLease>,
    history: Box<[ActivationState]>,
    receipts: Box<[PluginActivationReceipt]>,
}

impl PluginActivationSnapshot {
    fn bounded_receipts(receipts: Vec<PluginActivationReceipt>) -> Box<[PluginActivationReceipt]> {
        assert!(receipts.len() <= MAX_ACTIVATION_RECEIPTS);
        receipts.into_boxed_slice()
    }

    fn pre_start(request: &PluginActivationRequest, state: ActivationState) -> Self {
        Self {
            activation_id: request.activation_id.clone(),
            package_digest: request.package.package_digest(),
            generation: request.package.generation(),
            negotiation_snapshot: request.package.negotiation_snapshot(),
            state,
            start_intent: None,
            process_lease: None,
            generation_lease: None,
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
        receipts: Box<[PluginActivationReceipt]>,
    ) -> Self {
        Self {
            activation_id: request.activation_id.clone(),
            package_digest: request.package.package_digest(),
            generation: request.package.generation(),
            negotiation_snapshot: request.package.negotiation_snapshot(),
            state,
            start_intent: Some(start_intent),
            process_lease,
            generation_lease: Some(generation_lease),
            history: Vec::new().into_boxed_slice(),
            receipts,
        }
    }

    fn started(
        request: &PluginActivationRequest,
        state: ActivationState,
        start_intent: PluginStartIntent,
        process_lease: Option<PluginProcessLease>,
        generation_lease: PluginGenerationReadLease,
        negotiated: bool,
        receipts: Box<[PluginActivationReceipt]>,
    ) -> Self {
        let mut snapshot = Self::post_start(
            request,
            state,
            start_intent,
            process_lease,
            generation_lease,
            receipts,
        );
        let mut history = vec![ActivationState::Verified, ActivationState::Starting];
        if negotiated {
            history.push(ActivationState::Negotiating);
        }
        history.push(state);
        snapshot.history = history.into_boxed_slice();
        snapshot
    }

    pub fn activation_id(&self) -> &PluginActivationId {
        &self.activation_id
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

    fn record(&mut self, state: ActivationState) {
        let mut history = self.history.to_vec();
        history.push(state);
        self.history = history.into_boxed_slice();
    }

    /// Consumes Active and closes dispatch admission without duplicating its lease.
    pub fn begin_draining(mut self) -> Result<Self, Box<(Self, PluginLifecycleError)>> {
        if self.state != ActivationState::Active {
            return Err(Box::new((self, PluginLifecycleError::InvalidTransition)));
        }
        self.state = ActivationState::Draining;
        self.record(ActivationState::Draining);
        Ok(self)
    }

    /// Consumes Draining only when opaque backend evidence is bound to this exact activation.
    pub fn terminal(
        mut self,
        evidence: PluginTerminalEvidence,
    ) -> Result<Self, Box<(Self, PluginLifecycleError)>> {
        if self.state != ActivationState::Draining || !evidence.matches(&self) {
            return Err(Box::new((
                self,
                PluginLifecycleError::InvalidTerminalEvidence,
            )));
        }
        self.state = ActivationState::Terminal;
        self.record(ActivationState::Terminal);
        self.process_lease = None;
        self.generation_lease = None;
        Ok(self)
    }

    /// Consumes Draining and retains the exact leases for reconciliation.
    pub fn uncertain(mut self) -> Result<Self, Box<(Self, PluginLifecycleError)>> {
        if self.state != ActivationState::Draining {
            return Err(Box::new((self, PluginLifecycleError::InvalidTransition)));
        }
        self.state = ActivationState::Uncertain;
        self.record(ActivationState::Uncertain);
        Ok(self)
    }
}

/// Opaque terminal evidence issued by a certified backend.
#[derive(Debug)]
pub struct PluginTerminalEvidence {
    activation_id: PluginActivationId,
    package_digest: PluginDigest,
    generation: PluginGeneration,
    reservation: [u8; 32],
}

impl PluginTerminalEvidence {
    fn matches(&self, snapshot: &PluginActivationSnapshot) -> bool {
        self.activation_id == snapshot.activation_id
            && self.package_digest == snapshot.package_digest
            && self.generation == snapshot.generation
            && snapshot
                .start_intent
                .as_ref()
                .is_some_and(|intent| self.reservation == *intent.reservation())
    }

    #[cfg(test)]
    pub(crate) fn certified(snapshot: &PluginActivationSnapshot) -> Self {
        Self {
            activation_id: snapshot.activation_id.clone(),
            package_digest: snapshot.package_digest,
            generation: snapshot.generation,
            reservation: *snapshot
                .start_intent
                .as_ref()
                .expect("certified terminal evidence requires a start intent")
                .reservation(),
        }
    }
}

/// Invalid activation lifecycle operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PluginLifecycleError {
    InvalidTransition,
    InvalidTerminalEvidence,
}

/// Caller-supplied correlation values plus one registry-verified package.
#[derive(Debug)]
pub struct PluginActivationRequest {
    package: VerifiedPluginPackage,
    activation_id: PluginActivationId,
    host_nonce: Nonce,
    session_id: ProtocolSessionId,
}

impl PluginActivationRequest {
    /// Creates an activation request. Registry authority owns all profile, metadata and generation choices.
    pub fn new(
        package: VerifiedPluginPackage,
        activation_id: PluginActivationId,
        host_nonce: Nonce,
        session_id: ProtocolSessionId,
    ) -> Self {
        Self {
            package,
            activation_id,
            host_nonce,
            session_id,
        }
    }

    /// Starts the process and performs the registry-bound v2 bootstrap protocol.
    /// Legacy convenience entry point: without durable reservation authority it
    /// intentionally cannot cross the process boundary.
    pub fn activate(
        &self,
        _: &mut dyn PluginProcessPort,
        _: &mut dyn PluginTransportPort,
        _: &dyn PluginGenerationPort,
    ) -> PluginActivationSnapshot {
        PluginActivationSnapshot::pre_start(self, ActivationState::Verified)
    }

    /// Starts only after a durable start reservation was obtained.
    pub fn activate_with_reservation(
        &self,
        process: &mut dyn PluginProcessPort,
        transport: &mut dyn PluginTransportPort,
        generations: &dyn PluginGenerationPort,
        start_intents: &dyn PluginStartIntentPort,
    ) -> PluginActivationSnapshot {
        let generation = self.package.generation();
        let generation_lease = match generations.acquire_read_lease(&self.activation_id) {
            Ok(lease) if lease.matches(&self.activation_id, generation) => lease,
            _ => return PluginActivationSnapshot::pre_start(self, ActivationState::Verified),
        };
        let start_intent = match start_intents.reserve(
            &self.activation_id,
            self.package.package_digest(),
            generation,
        ) {
            Ok(intent)
                if intent.matches(
                    &self.activation_id,
                    self.package.package_digest(),
                    generation,
                ) =>
            {
                intent
            }
            _ => return PluginActivationSnapshot::pre_start(self, ActivationState::Verified),
        };
        debug_assert!(start_intent.matches(
            &self.activation_id,
            self.package.package_digest(),
            generation
        ));
        let receipts = PluginActivationSnapshot::bounded_receipts(vec![
            PluginActivationReceipt::StartAttempted,
        ]);
        let process_lease = match process.start(&start_intent, &generation_lease) {
            Ok(lease) if lease.matches(&start_intent) => lease,
            Ok(_) | Err(PluginProcessPortError::ResponseLost) => {
                return PluginActivationSnapshot::started(
                    self,
                    ActivationState::Uncertain,
                    start_intent,
                    None,
                    generation_lease,
                    false,
                    receipts,
                );
            }
            Err(PluginProcessPortError::BackendUnavailable | PluginProcessPortError::Rejected) => {
                let snapshot = PluginActivationSnapshot {
                    receipts: PluginActivationSnapshot::bounded_receipts(vec![
                        PluginActivationReceipt::StartAttempted,
                        PluginActivationReceipt::StartProvenNotStarted,
                    ]),
                    ..PluginActivationSnapshot::pre_start(self, ActivationState::Verified)
                };
                return snapshot;
            }
        };
        let uncertain = |start_intent, lease, generation_lease, negotiated| {
            PluginActivationSnapshot::started(
                self,
                ActivationState::Uncertain,
                start_intent,
                lease,
                generation_lease,
                negotiated,
                receipts.clone(),
            )
        };
        let hello = match self.exchange_host_hello(transport) {
            Some(value) => value,
            None => return uncertain(start_intent, Some(process_lease), generation_lease, true),
        };
        let plugin_nonce = match self.validate_plugin_hello(&hello) {
            Some(value) => value,
            None => return uncertain(start_intent, Some(process_lease), generation_lease, true),
        };
        if !self.exchange_profile_selection(transport, plugin_nonce) {
            return uncertain(start_intent, Some(process_lease), generation_lease, true);
        }
        if generations
            .ready_compare_and_set(&generation_lease)
            .is_err()
        {
            return uncertain(start_intent, Some(process_lease), generation_lease, true);
        }
        PluginActivationSnapshot::started(
            self,
            ActivationState::Active,
            start_intent,
            Some(process_lease),
            generation_lease,
            true,
            receipts,
        )
    }

    pub const fn host_nonce(&self) -> Nonce {
        self.host_nonce
    }
    pub const fn session_id(&self) -> ProtocolSessionId {
        self.session_id
    }
    pub const fn generation(&self) -> PluginGeneration {
        self.package.generation()
    }
    pub fn protocol_profile(&self) -> gocode_plugin_protocol::profile::ProtocolProfileRef {
        self.package.selected_profile()
    }
    pub const fn package_digest(&self) -> PluginDigest {
        self.package.package_digest()
    }

    fn exchange_host_hello(&self, transport: &mut dyn PluginTransportPort) -> Option<PluginHello> {
        let metadata = self.package.plugin_hello_metadata();
        match self.exchange(
            transport,
            BootstrapMessage::HostHello(HostHello {
                nonce: self.host_nonce,
                host_identity: metadata.host_identity,
                supported_profiles: self.package.advertised_profiles(),
                negotiation_snapshot: self.package.negotiation_snapshot(),
            }),
        )? {
            BootstrapMessage::PluginHello(hello) => Some(hello),
            _ => None,
        }
    }

    fn validate_plugin_hello(&self, hello: &PluginHello) -> Option<Nonce> {
        let metadata = self.package.plugin_hello_metadata();
        let profiles = self.package.advertised_profiles();
        let package_digest = PackageDigest::new(
            DigestAlgorithm::Sha256,
            *self.package.package_digest().as_bytes(),
        );
        if hello.host_nonce != self.host_nonce
            || hello.host_identity != metadata.host_identity
            || hello.package_id != metadata.package_id
            || hello.package_digest != package_digest
            || hello.package_version != metadata.package_version
            || hello.manifest_digest != metadata.manifest_digest
            || hello.plugin_identity != metadata.plugin_identity
            || hello.target_identity != metadata.target_identity
            || hello.entrypoint != metadata.entrypoint
            || hello.supported_profiles != profiles
        {
            return None;
        }
        Some(hello.plugin_nonce)
    }

    fn exchange_profile_selection(
        &self,
        transport: &mut dyn PluginTransportPort,
        plugin_nonce: Nonce,
    ) -> bool {
        let profile = self.protocol_profile();
        let selected = BootstrapMessage::ProfileSelected(ProfileSelected {
            host_nonce: self.host_nonce,
            plugin_nonce,
            session_id: self.session_id,
            profile_id: profile.profile_id().clone(),
            profile_digest: *profile.profile_digest(),
        });
        matches!(self.exchange_v2(transport, selected), Some(SelectionAcknowledgedV2 { host_nonce, plugin_nonce: peer_nonce, session_id, profile_id, profile_digest }) if host_nonce == self.host_nonce && peer_nonce == plugin_nonce && session_id == self.session_id && profile_id == *profile.profile_id() && profile_digest == *profile.profile_digest())
    }

    fn exchange(
        &self,
        transport: &mut dyn PluginTransportPort,
        message: BootstrapMessage,
    ) -> Option<BootstrapMessage> {
        let outbound = encode_frame(
            &message,
            &FrameLimits {
                max_frame_bytes: MAX_BOOTSTRAP_FRAME_BYTES,
            },
        )
        .ok()?;
        let mut inbound = [0; MAX_BOOTSTRAP_FRAME_BYTES];
        transport
            .send(PluginBootstrapFrame::outbound(outbound))
            .ok()?;
        let size = transport.receive(&mut inbound).ok()?;
        if size > inbound.len() {
            return None;
        }
        decode_frame(
            &inbound[..size],
            &DecodeLimits {
                max_frame_bytes: MAX_BOOTSTRAP_FRAME_BYTES,
                ..DecodeLimits::default()
            },
        )
        .ok()
    }

    fn exchange_v2(
        &self,
        transport: &mut dyn PluginTransportPort,
        message: BootstrapMessage,
    ) -> Option<SelectionAcknowledgedV2> {
        let outbound = encode_frame(
            &message,
            &FrameLimits {
                max_frame_bytes: MAX_BOOTSTRAP_FRAME_BYTES,
            },
        )
        .ok()?;
        let mut inbound = [0; MAX_BOOTSTRAP_FRAME_BYTES];
        transport
            .send(PluginBootstrapFrame::outbound(outbound))
            .ok()?;
        let size = transport.receive(&mut inbound).ok()?;
        if size > inbound.len() {
            return None;
        }
        decode_codec_frame(
            &inbound[..size],
            &DecodeLimits {
                max_frame_bytes: MAX_BOOTSTRAP_FRAME_BYTES,
                ..DecodeLimits::default()
            },
        )
        .ok()
    }
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;

    use super::*;
    use crate::{
        PluginAuthorityPort, PluginAuthorityRegistry, PluginClass, PluginGenerationPortError,
        PluginProcessPortError, PluginTransportPortError,
    };
    use gocode_plugin_protocol::bootstrap::{HostExecutionIdentity, PluginHello};
    use gocode_plugin_protocol::digest::ProfileDigest;
    use gocode_plugin_protocol::id::PluginIdentity;
    use gocode_plugin_protocol::id::ProfileId;
    use gocode_plugin_protocol::profile::{BoundedProfileRefVec, ProtocolProfileRef};
    #[test]
    fn certified_evidence_can_terminalize_exact_draining_snapshot_once() {
        let id = PluginActivationId::new("fixture").unwrap();
        let digest = PluginDigest::from_bytes([1; 32]);
        let generation = PluginGeneration::INITIAL;
        let active = active_snapshot(id, digest, generation);
        let evidence = PluginTerminalEvidence::certified(&active);
        let terminal = active.begin_draining().unwrap().terminal(evidence).unwrap();
        assert_eq!(terminal.state(), ActivationState::Terminal);
    }

    #[test]
    fn invalid_terminal_evidence_returns_the_original_draining_snapshot_for_retry() {
        let id = PluginActivationId::new("retry-terminal").unwrap();
        let digest = PluginDigest::from_bytes([1; 32]);
        let generation = PluginGeneration::INITIAL;
        let draining = active_snapshot(id.clone(), digest, generation)
            .begin_draining()
            .unwrap();
        let other = active_snapshot(
            PluginActivationId::new("other").unwrap(),
            digest,
            generation,
        );
        let invalid_evidence = PluginTerminalEvidence::certified(&other);
        let valid_evidence = PluginTerminalEvidence::certified(&draining);

        let (draining, error) = *draining.terminal(invalid_evidence).unwrap_err();
        assert_eq!(error, PluginLifecycleError::InvalidTerminalEvidence);
        assert_eq!(draining.state(), ActivationState::Draining);
        assert!(draining.process_lease.is_some());
        assert!(draining.generation_lease.is_some());

        assert_eq!(
            draining.terminal(valid_evidence).unwrap().state(),
            ActivationState::Terminal
        );
    }

    #[test]
    fn certified_fixtures_exercise_handshake_and_fail_closed_branches() {
        let request = request();
        let profile = request.protocol_profile();
        let active = request.activate_with_reservation(
            &mut Process::default(),
            &mut Transport::new(vec![
                hello(&request, profile.clone()),
                ack(&request, profile.clone()),
            ]),
            &Generation::current(),
            &Starts,
        );
        assert_eq!(active.state(), ActivationState::Active);
        assert_eq!(
            active.transition_history(),
            [
                ActivationState::Verified,
                ActivationState::Starting,
                ActivationState::Negotiating,
                ActivationState::Active,
            ]
        );

        let reflected = BootstrapMessage::ProfileSelected(ProfileSelected {
            host_nonce: request.host_nonce(),
            plugin_nonce: Nonce::from_bytes([2; 16]),
            session_id: request.session_id(),
            profile_id: profile.profile_id().clone(),
            profile_digest: *profile.profile_digest(),
        });
        assert_eq!(
            request
                .activate_with_reservation(
                    &mut Process::default(),
                    &mut Transport::new(vec![hello(&request, profile.clone()), reflected]),
                    &Generation::current(),
                    &Starts
                )
                .state(),
            ActivationState::Uncertain
        );

        let mut wrong_identity = hello(&request, profile.clone());
        if let BootstrapMessage::PluginHello(value) = &mut wrong_identity {
            value.plugin_identity =
                HostExecutionIdentity::Plugin(PluginIdentity::new("different-plugin").unwrap());
        }
        assert_eq!(
            request
                .activate_with_reservation(
                    &mut Process::default(),
                    &mut Transport::new(vec![wrong_identity]),
                    &Generation::current(),
                    &Starts
                )
                .state(),
            ActivationState::Uncertain
        );

        let mut wrong_nonce = hello(&request, profile.clone());
        if let BootstrapMessage::PluginHello(value) = &mut wrong_nonce {
            value.host_nonce = Nonce::from_bytes([9; 16]);
        }
        assert_eq!(
            request
                .activate_with_reservation(
                    &mut Process::default(),
                    &mut Transport::new(vec![wrong_nonce]),
                    &Generation::current(),
                    &Starts
                )
                .state(),
            ActivationState::Uncertain
        );

        let recombined = ProtocolProfileRef::new(
            profile.profile_id().clone(),
            ProfileDigest::from_bytes([9; 32]),
        );
        assert_eq!(
            request
                .activate_with_reservation(
                    &mut Process::default(),
                    &mut Transport::new(vec![hello(&request, recombined)]),
                    &Generation::current(),
                    &Starts
                )
                .state(),
            ActivationState::Uncertain
        );
        assert_eq!(
            request
                .activate_with_reservation(
                    &mut Process::default(),
                    &mut Transport::oversized(),
                    &Generation::current(),
                    &Starts
                )
                .state(),
            ActivationState::Uncertain
        );
        assert_eq!(
            request
                .activate_with_reservation(
                    &mut Process::default(),
                    &mut Transport::new(vec![
                        hello(&request, profile.clone()),
                        ack(&request, profile)
                    ]),
                    &Generation {
                        fail_ready: true,
                        generation: PluginGeneration::INITIAL
                    },
                    &Starts
                )
                .state(),
            ActivationState::Uncertain
        );

        let uncertain = active.begin_draining().unwrap().uncertain().unwrap();
        assert_eq!(uncertain.state(), ActivationState::Uncertain);
    }

    fn request() -> PluginActivationRequest {
        let source = fixture_source();
        let package = PluginAuthorityRegistry::built_in()
            .verifier_for(&source)
            .unwrap()
            .verify(source)
            .unwrap();
        request_with(package, "fixture-handshake")
    }

    fn fixture_source() -> crate::PluginPackageSource {
        crate::PluginPackageCapture::capture(
            crate::PluginPackageContent::new(
                b"gocode-plugin-host/builtin-package-v1".to_vec(),
                b"GOCODE_PLUGIN_MANIFEST_V1\npackage_id=builtin\npackage_version=1.0.0\nhost_identity=host\nplugin_identity=plugin\ntarget_identity=target\nentrypoint=entrypoint\n".to_vec(),
                b"gocode-plugin-host/builtin-entrypoint-v1".to_vec(),
                b"GOCODE_PLUGIN_PROFILE_V1\nprofile_id=builtin-profile-v2\n".to_vec(),
                b"gocode-plugin-host/builtin-trust-binding-v1".to_vec(),
            ),
            PluginClass::Extension,
        )
    }

    fn request_with(
        package: crate::VerifiedPluginPackage,
        activation_id: &str,
    ) -> PluginActivationRequest {
        PluginActivationRequest::new(
            package,
            PluginActivationId::new(activation_id).unwrap(),
            Nonce::from_bytes([1; 16]),
            ProtocolSessionId::from_bytes([7, 0, 0, 0, 0, 0, 0x70, 0, 0x80, 0, 0, 0, 0, 0, 0, 1]),
        )
    }

    #[test]
    fn registry_advance_requires_reverification_before_a_fresh_generation_can_activate() {
        let mut registry = PluginAuthorityRegistry::built_in();
        let old_source = fixture_source();
        let old_package = registry
            .verifier_for(&old_source)
            .unwrap()
            .verify(old_source)
            .unwrap();
        let old_request = request_with(old_package, "generation-old");
        let initial_snapshot_binding = old_request.package.negotiation_snapshot();
        let mut initial_process = CountingProcess::success();
        let mut initial_transport = exact_v2_transport(&old_request);
        let initial_generation = CountingRegistry::new(&registry);
        let active = old_request.activate_with_reservation(
            &mut initial_process,
            &mut initial_transport,
            &initial_generation,
            &Starts,
        );
        assert_eq!(active.state(), ActivationState::Active);
        assert_eq!(active.negotiation_snapshot(), initial_snapshot_binding);
        assert_stage_case(
            &active,
            ActivationState::Active,
            &[
                ActivationState::Verified,
                ActivationState::Starting,
                ActivationState::Negotiating,
                ActivationState::Active,
            ],
            &[PluginActivationReceipt::StartAttempted],
            true,
            &initial_process,
            &initial_transport,
            &initial_generation,
            (1, 2, 2, 1),
        );
        registry.advance().unwrap();

        let mut stale_process = CountingProcess::success();
        let mut stale_transport = CountingTransport::new(vec![]);
        let stale_generation = CountingRegistry::new(&registry);
        let stale = old_request.activate_with_reservation(
            &mut stale_process,
            &mut stale_transport,
            &stale_generation,
            &Starts,
        );
        assert_stage_case(
            &stale,
            ActivationState::Verified,
            &[ActivationState::Verified],
            &[],
            false,
            &stale_process,
            &stale_transport,
            &stale_generation,
            (0, 0, 0, 0),
        );

        let new_source = fixture_source();
        let new_package = registry
            .verifier_for(&new_source)
            .unwrap()
            .verify(new_source)
            .unwrap();
        let new_request = request_with(new_package, "generation-new");
        let renewed_snapshot_binding = new_request.package.negotiation_snapshot();
        let mut renewed_process = CountingProcess::success();
        let mut renewed_transport = exact_v2_transport(&new_request);
        let renewed_generation = CountingRegistry::new(&registry);
        let renewed = new_request.activate_with_reservation(
            &mut renewed_process,
            &mut renewed_transport,
            &renewed_generation,
            &Starts,
        );
        assert_eq!(renewed.state(), ActivationState::Active);
        assert_eq!(renewed.negotiation_snapshot(), renewed_snapshot_binding);
        assert_eq!(renewed.generation(), PluginGeneration::new(2).unwrap());
        assert_stage_case(
            &renewed,
            ActivationState::Active,
            &[
                ActivationState::Verified,
                ActivationState::Starting,
                ActivationState::Negotiating,
                ActivationState::Active,
            ],
            &[PluginActivationReceipt::StartAttempted],
            true,
            &renewed_process,
            &renewed_transport,
            &renewed_generation,
            (1, 2, 2, 1),
        );
        assert_ne!(active.generation(), renewed.generation());
        assert_eq!(
            active.retained_generation_lease_generation(),
            Some(PluginGeneration::INITIAL)
        );
        assert_eq!(
            renewed.retained_generation_lease_generation(),
            Some(PluginGeneration::new(2).unwrap())
        );
        assert_ne!(
            active.negotiation_snapshot(),
            renewed.negotiation_snapshot()
        );
    }
    fn active_snapshot(
        id: PluginActivationId,
        digest: PluginDigest,
        generation: PluginGeneration,
    ) -> PluginActivationSnapshot {
        let intent = PluginStartIntent::issued(id.clone(), digest, generation, [1; 32]);
        PluginActivationSnapshot {
            activation_id: id.clone(),
            package_digest: digest,
            generation,
            negotiation_snapshot: ProtocolNegotiationSnapshotDigest::from_bytes([1; 32]),
            state: ActivationState::Active,
            process_lease: Some(PluginProcessLease::certified(&intent)),
            start_intent: Some(intent),
            generation_lease: Some(PluginGenerationReadLease::issued(id, generation)),
            history: vec![
                ActivationState::Verified,
                ActivationState::Starting,
                ActivationState::Negotiating,
                ActivationState::Active,
            ]
            .into_boxed_slice(),
            receipts: PluginActivationSnapshot::bounded_receipts(vec![
                PluginActivationReceipt::StartAttempted,
            ]),
        }
    }
    fn hello(request: &PluginActivationRequest, profile: ProtocolProfileRef) -> BootstrapMessage {
        let mut profiles = BoundedProfileRefVec::new();
        profiles.push(profile).unwrap();
        let metadata = request.package.plugin_hello_metadata();
        BootstrapMessage::PluginHello(PluginHello {
            host_nonce: request.host_nonce(),
            plugin_nonce: Nonce::from_bytes([2; 16]),
            host_identity: metadata.host_identity,
            package_id: metadata.package_id,
            package_digest: PackageDigest::new(
                DigestAlgorithm::Sha256,
                *request.package_digest().as_bytes(),
            ),
            package_version: metadata.package_version,
            manifest_digest: metadata.manifest_digest,
            plugin_identity: metadata.plugin_identity,
            target_identity: metadata.target_identity,
            entrypoint: metadata.entrypoint,
            supported_profiles: profiles,
        })
    }
    fn ack(request: &PluginActivationRequest, profile: ProtocolProfileRef) -> BootstrapMessage {
        // Transport fixture encodes this V2 response only after ProfileSelected.
        BootstrapMessage::SelectionAcknowledged(
            gocode_plugin_protocol::bootstrap::SelectionAcknowledged {
                host_nonce: request.host_nonce(),
                plugin_nonce: Nonce::from_bytes([2; 16]),
                session_id: request.session_id(),
                profile_id: profile.profile_id().clone(),
                profile_digest: *profile.profile_digest(),
            },
        )
    }
    #[test]
    fn stale_generation_is_rejected_before_process_start() {
        let mut process = Process::default();
        let snapshot = request().activate_with_reservation(
            &mut process,
            &mut Transport::new(vec![]),
            &Generation::at(PluginGeneration::new(2).unwrap()),
            &Starts,
        );
        assert_eq!(snapshot.state(), ActivationState::Verified);
        assert_eq!(process.calls, 0);
        assert_eq!(snapshot.transition_history(), [ActivationState::Verified]);
    }

    #[test]
    fn activation_stage_matrix_stale_generation_has_no_boundary_calls() {
        let mut process = CountingProcess::success();
        let mut transport = CountingTransport::new(vec![]);
        let generation = CountingGeneration::at(PluginGeneration::new(2).unwrap());

        let snapshot =
            request().activate_with_reservation(&mut process, &mut transport, &generation, &Starts);

        assert_eq!(snapshot.state(), ActivationState::Verified);
        assert_eq!(snapshot.transition_history(), [ActivationState::Verified]);
        assert_eq!(snapshot.attempt_receipts(), []);
        assert_no_reconciliation_leases(&snapshot);
        assert_eq!(process.start_calls, 0);
        assert_eq!(transport.write_calls, 0);
        assert_eq!(transport.read_calls, 0);
        assert_eq!(generation.ready_cas_calls.get(), 0);
    }

    #[test]
    fn activation_stage_matrix_backend_unavailable_stops_before_transport() {
        let request = request();
        let mut process = CountingProcess::backend_unavailable();
        let mut transport = CountingTransport::new(vec![]);
        let generation = CountingGeneration::current();
        let snapshot =
            request.activate_with_reservation(&mut process, &mut transport, &generation, &Starts);
        assert_stage_case(
            &snapshot,
            ActivationState::Verified,
            &[ActivationState::Verified],
            &[
                PluginActivationReceipt::StartAttempted,
                PluginActivationReceipt::StartProvenNotStarted,
            ],
            false,
            &process,
            &transport,
            &generation,
            (1, 0, 0, 0),
        );
    }

    #[test]
    fn activation_stage_matrix_v1_downgrade_to_legacy_profile_is_uncertain() {
        let request = request();
        let mut peer = peer_hello(&request);
        let authority = request.protocol_profile();
        assert_eq!(authority.profile_id().as_str(), "builtin-profile-v2");
        assert_eq!(
            authority.profile_digest().as_bytes(),
            request.package.protocol_profile_digest().as_bytes()
        );
        let mut legacy_profiles = BoundedProfileRefVec::new();
        legacy_profiles
            .push(ProtocolProfileRef::new(
                ProfileId::new("builtin-profile-v1").unwrap(),
                ProfileDigest::from_bytes([1; 32]),
            ))
            .unwrap();
        peer.supported_profiles = legacy_profiles;
        let mut process = CountingProcess::success();
        let mut transport =
            CountingTransport::new(vec![WireResponse::V1(BootstrapMessage::PluginHello(peer))]);
        let generation = CountingGeneration::current();
        let snapshot =
            request.activate_with_reservation(&mut process, &mut transport, &generation, &Starts);
        assert_uncertain_after_first_exchange(&snapshot, &process, &transport, &generation);
    }

    #[test]
    fn activation_stage_matrix_plugin_hello_identity_mismatch_is_uncertain() {
        let request = request();
        let mut peer = peer_hello(&request);
        peer.plugin_identity =
            HostExecutionIdentity::Plugin(PluginIdentity::new("different-plugin").unwrap());
        assert_first_exchange_failure(request, BootstrapMessage::PluginHello(peer));
    }

    #[test]
    fn activation_stage_matrix_nonce_mismatch_is_uncertain() {
        let request = request();
        let mut peer = peer_hello(&request);
        peer.host_nonce = Nonce::from_bytes([9; 16]);
        assert_first_exchange_failure(request, BootstrapMessage::PluginHello(peer));
    }

    #[test]
    fn activation_stage_matrix_profile_recombination_is_uncertain() {
        let request = request();
        let mut peer = peer_hello(&request);
        let profile = request.protocol_profile();
        let mut profiles = BoundedProfileRefVec::new();
        profiles
            .push(ProtocolProfileRef::new(
                profile.profile_id().clone(),
                ProfileDigest::from_bytes([9; 32]),
            ))
            .unwrap();
        peer.supported_profiles = profiles;
        assert_first_exchange_failure(request, BootstrapMessage::PluginHello(peer));
    }

    #[test]
    fn activation_stage_matrix_oversized_first_inbound_frame_is_uncertain() {
        let request = request();
        let mut process = CountingProcess::success();
        let mut transport = CountingTransport::oversized();
        let generation = CountingGeneration::current();
        let snapshot =
            request.activate_with_reservation(&mut process, &mut transport, &generation, &Starts);
        assert_uncertain_after_first_exchange(&snapshot, &process, &transport, &generation);
    }

    #[test]
    fn activation_stage_matrix_reflected_v1_selection_as_ack_is_uncertain() {
        let request = request();
        let profile = request.protocol_profile();
        let reflected = BootstrapMessage::ProfileSelected(ProfileSelected {
            host_nonce: request.host_nonce(),
            plugin_nonce: Nonce::from_bytes([2; 16]),
            session_id: request.session_id(),
            profile_id: profile.profile_id().clone(),
            profile_digest: *profile.profile_digest(),
        });
        let mut process = CountingProcess::success();
        let mut transport = CountingTransport::new(vec![
            WireResponse::V1(BootstrapMessage::PluginHello(peer_hello(&request))),
            WireResponse::V1(reflected),
        ]);
        let generation = CountingGeneration::current();
        let snapshot =
            request.activate_with_reservation(&mut process, &mut transport, &generation, &Starts);
        assert_stage_case(
            &snapshot,
            ActivationState::Uncertain,
            &[
                ActivationState::Verified,
                ActivationState::Starting,
                ActivationState::Negotiating,
                ActivationState::Uncertain,
            ],
            &[PluginActivationReceipt::StartAttempted],
            true,
            &process,
            &transport,
            &generation,
            (1, 2, 2, 0),
        );
    }

    #[test]
    fn activation_stage_matrix_ready_cas_failure_is_uncertain() {
        let request = request();
        let mut process = CountingProcess::success();
        let mut transport = exact_v2_transport(&request);
        let generation = CountingGeneration::failing_ready();
        let snapshot =
            request.activate_with_reservation(&mut process, &mut transport, &generation, &Starts);
        assert_stage_case(
            &snapshot,
            ActivationState::Uncertain,
            &[
                ActivationState::Verified,
                ActivationState::Starting,
                ActivationState::Negotiating,
                ActivationState::Uncertain,
            ],
            &[PluginActivationReceipt::StartAttempted],
            true,
            &process,
            &transport,
            &generation,
            (1, 2, 2, 1),
        );
    }

    #[test]
    fn activation_stage_matrix_exact_v2_success_is_active() {
        let request = request();
        let mut process = CountingProcess::success();
        let mut transport = exact_v2_transport(&request);
        let generation = CountingGeneration::current();
        let snapshot =
            request.activate_with_reservation(&mut process, &mut transport, &generation, &Starts);
        assert_stage_case(
            &snapshot,
            ActivationState::Active,
            &[
                ActivationState::Verified,
                ActivationState::Starting,
                ActivationState::Negotiating,
                ActivationState::Active,
            ],
            &[PluginActivationReceipt::StartAttempted],
            true,
            &process,
            &transport,
            &generation,
            (1, 2, 2, 1),
        );
    }

    #[test]
    fn lifecycle_terminal_has_one_drain_and_one_terminal_call_with_no_reconciliation_leases() {
        let active = active_snapshot(
            PluginActivationId::new("counted-terminal").unwrap(),
            PluginDigest::from_bytes([5; 32]),
            PluginGeneration::INITIAL,
        );
        let mut lifecycle = CountingLifecycle::default();
        let terminal = lifecycle.terminal(active).unwrap();

        assert_eq!(lifecycle.drain_calls, 1);
        assert_eq!(lifecycle.terminal_calls, 1);
        assert_eq!(terminal.state(), ActivationState::Terminal);
        assert_eq!(
            terminal.transition_history(),
            [
                ActivationState::Verified,
                ActivationState::Starting,
                ActivationState::Negotiating,
                ActivationState::Active,
                ActivationState::Draining,
                ActivationState::Terminal,
            ]
        );
        assert_eq!(
            terminal.attempt_receipts(),
            [PluginActivationReceipt::StartAttempted]
        );
        assert_terminal_reconciliation_leases_cleared(&terminal);
    }

    #[test]
    fn lifecycle_uncertain_has_one_drain_and_no_terminal_call_with_retained_leases() {
        let active = active_snapshot(
            PluginActivationId::new("counted-uncertain").unwrap(),
            PluginDigest::from_bytes([6; 32]),
            PluginGeneration::INITIAL,
        );
        let mut lifecycle = CountingLifecycle::default();
        let uncertain = lifecycle.uncertain(active).unwrap();

        assert_eq!(lifecycle.drain_calls, 1);
        assert_eq!(lifecycle.terminal_calls, 0);
        assert_eq!(uncertain.state(), ActivationState::Uncertain);
        assert_eq!(
            uncertain.transition_history(),
            [
                ActivationState::Verified,
                ActivationState::Starting,
                ActivationState::Negotiating,
                ActivationState::Active,
                ActivationState::Draining,
                ActivationState::Uncertain,
            ]
        );
        assert_eq!(
            uncertain.attempt_receipts(),
            [PluginActivationReceipt::StartAttempted]
        );
        assert!(uncertain.start_intent.is_some());
        assert!(uncertain.process_lease.is_some());
        assert!(uncertain.generation_lease.is_some());
    }

    #[test]
    fn lifecycle_invalid_evidence_then_retry_has_one_drain_and_two_terminal_calls() {
        let active = active_snapshot(
            PluginActivationId::new("counted-retry").unwrap(),
            PluginDigest::from_bytes([7; 32]),
            PluginGeneration::INITIAL,
        );
        let other = active_snapshot(
            PluginActivationId::new("counted-other").unwrap(),
            PluginDigest::from_bytes([7; 32]),
            PluginGeneration::INITIAL,
        );
        let mut lifecycle = CountingLifecycle::default();
        let draining = lifecycle.drain(active).unwrap();
        let valid = PluginTerminalEvidence::certified(&draining);
        let retained = lifecycle
            .terminal_with(draining, PluginTerminalEvidence::certified(&other))
            .unwrap_err();
        assert_eq!(lifecycle.drain_calls, 1);
        assert_eq!(lifecycle.terminal_calls, 1);
        assert_eq!(retained.state(), ActivationState::Draining);
        assert_eq!(
            retained.transition_history(),
            [
                ActivationState::Verified,
                ActivationState::Starting,
                ActivationState::Negotiating,
                ActivationState::Active,
                ActivationState::Draining,
            ]
        );
        assert_eq!(
            retained.attempt_receipts(),
            [PluginActivationReceipt::StartAttempted]
        );
        assert!(retained.start_intent.is_some());
        assert!(retained.process_lease.is_some());
        assert!(retained.generation_lease.is_some());
        let terminal = lifecycle.terminal_with(*retained, valid).unwrap();

        assert_eq!(lifecycle.drain_calls, 1);
        assert_eq!(lifecycle.terminal_calls, 2);
        assert_eq!(terminal.state(), ActivationState::Terminal);
        assert_eq!(
            terminal.transition_history(),
            [
                ActivationState::Verified,
                ActivationState::Starting,
                ActivationState::Negotiating,
                ActivationState::Active,
                ActivationState::Draining,
                ActivationState::Terminal,
            ]
        );
        assert_eq!(
            terminal.attempt_receipts(),
            [PluginActivationReceipt::StartAttempted]
        );
        assert_terminal_reconciliation_leases_cleared(&terminal);
    }

    fn assert_first_exchange_failure(request: PluginActivationRequest, response: BootstrapMessage) {
        let mut process = CountingProcess::success();
        let mut transport = CountingTransport::new(vec![WireResponse::V1(response)]);
        let generation = CountingGeneration::current();
        let snapshot =
            request.activate_with_reservation(&mut process, &mut transport, &generation, &Starts);
        assert_uncertain_after_first_exchange(&snapshot, &process, &transport, &generation);
    }

    fn assert_uncertain_after_first_exchange(
        snapshot: &PluginActivationSnapshot,
        process: &CountingProcess,
        transport: &CountingTransport,
        generation: &impl ReadyCasCounter,
    ) {
        assert_stage_case(
            snapshot,
            ActivationState::Uncertain,
            &[
                ActivationState::Verified,
                ActivationState::Starting,
                ActivationState::Negotiating,
                ActivationState::Uncertain,
            ],
            &[PluginActivationReceipt::StartAttempted],
            true,
            process,
            transport,
            generation,
            (1, 1, 1, 0),
        );
    }

    #[allow(clippy::too_many_arguments)] // Matrix contract deliberately lists independent evidence dimensions.
    fn assert_stage_case(
        snapshot: &PluginActivationSnapshot,
        state: ActivationState,
        history: &[ActivationState],
        receipts: &[PluginActivationReceipt],
        retains_reconciliation_leases: bool,
        process: &CountingProcess,
        transport: &CountingTransport,
        generation: &impl ReadyCasCounter,
        counts: (usize, usize, usize, usize),
    ) {
        assert_eq!(snapshot.state(), state);
        assert_eq!(snapshot.transition_history(), history);
        assert_eq!(snapshot.attempt_receipts(), receipts);
        assert_eq!(
            snapshot.start_intent.is_some(),
            retains_reconciliation_leases
        );
        assert_eq!(
            snapshot.process_lease.is_some(),
            retains_reconciliation_leases
        );
        assert_eq!(
            snapshot.generation_lease.is_some(),
            retains_reconciliation_leases
        );
        assert_eq!(process.start_calls, counts.0);
        assert_eq!(transport.write_calls, counts.1);
        assert_eq!(transport.read_calls, counts.2);
        assert_eq!(generation.ready_cas_calls(), counts.3);
    }

    fn assert_no_reconciliation_leases(snapshot: &PluginActivationSnapshot) {
        assert!(snapshot.start_intent.is_none());
        assert!(snapshot.process_lease.is_none());
        assert!(snapshot.generation_lease.is_none());
    }

    fn assert_terminal_reconciliation_leases_cleared(snapshot: &PluginActivationSnapshot) {
        assert!(snapshot.start_intent.is_some());
        assert!(snapshot.process_lease.is_none());
        assert!(snapshot.generation_lease.is_none());
    }

    #[derive(Default)]
    struct CountingLifecycle {
        drain_calls: usize,
        terminal_calls: usize,
    }

    impl CountingLifecycle {
        fn drain(
            &mut self,
            snapshot: PluginActivationSnapshot,
        ) -> Result<PluginActivationSnapshot, Box<(PluginActivationSnapshot, PluginLifecycleError)>>
        {
            self.drain_calls += 1;
            snapshot.begin_draining()
        }

        fn terminal(
            &mut self,
            snapshot: PluginActivationSnapshot,
        ) -> Result<PluginActivationSnapshot, Box<(PluginActivationSnapshot, PluginLifecycleError)>>
        {
            let evidence = PluginTerminalEvidence::certified(&snapshot);
            let draining = self.drain(snapshot)?;
            self.terminal_calls += 1;
            draining.terminal(evidence)
        }

        fn uncertain(
            &mut self,
            snapshot: PluginActivationSnapshot,
        ) -> Result<PluginActivationSnapshot, Box<(PluginActivationSnapshot, PluginLifecycleError)>>
        {
            self.drain_calls += 1;
            snapshot.begin_draining()?.uncertain()
        }

        fn terminal_with(
            &mut self,
            snapshot: PluginActivationSnapshot,
            evidence: PluginTerminalEvidence,
        ) -> Result<PluginActivationSnapshot, Box<PluginActivationSnapshot>> {
            self.terminal_calls += 1;
            snapshot.terminal(evidence).map_err(|error| {
                let (snapshot, lifecycle_error) = *error;
                assert_eq!(
                    lifecycle_error,
                    PluginLifecycleError::InvalidTerminalEvidence
                );
                Box::new(snapshot)
            })
        }
    }

    #[test]
    fn activation_history_always_ends_in_snapshot_state() {
        let stale_generation = request().activate_with_reservation(
            &mut Process::default(),
            &mut Transport::new(vec![]),
            &Generation::at(PluginGeneration::new(2).unwrap()),
            &Starts,
        );
        let start_intent_unavailable = request().activate_with_reservation(
            &mut Process::default(),
            &mut Transport::new(vec![]),
            &Generation::current(),
            &UnavailableStarts,
        );
        let backend_unavailable = request().activate_with_reservation(
            &mut UnavailableProcess::default(),
            &mut Transport::new(vec![]),
            &Generation::current(),
            &Starts,
        );
        let rejected = request().activate_with_reservation(
            &mut RejectedProcess::default(),
            &mut Transport::new(vec![]),
            &Generation::current(),
            &Starts,
        );
        let response_lost = request().activate_with_reservation(
            &mut LostResponseProcess::default(),
            &mut Transport::new(vec![]),
            &Generation::current(),
            &Starts,
        );
        let negotiation_failed = request().activate_with_reservation(
            &mut Process::default(),
            &mut Transport::oversized(),
            &Generation::current(),
            &Starts,
        );
        let ready_cas_failed_request = request();
        let ready_cas_failed_profile = ready_cas_failed_request.protocol_profile();
        let ready_cas_failed = ready_cas_failed_request.activate_with_reservation(
            &mut Process::default(),
            &mut Transport::new(vec![
                hello(&ready_cas_failed_request, ready_cas_failed_profile.clone()),
                ack(&ready_cas_failed_request, ready_cas_failed_profile),
            ]),
            &Generation {
                fail_ready: true,
                generation: PluginGeneration::INITIAL,
            },
            &Starts,
        );
        let active = active_snapshot(
            PluginActivationId::new("history-active").unwrap(),
            PluginDigest::from_bytes([1; 32]),
            PluginGeneration::INITIAL,
        );
        let draining = active_snapshot(
            PluginActivationId::new("history-draining").unwrap(),
            PluginDigest::from_bytes([1; 32]),
            PluginGeneration::INITIAL,
        )
        .begin_draining()
        .unwrap();
        let terminal_active = active_snapshot(
            PluginActivationId::new("history-terminal").unwrap(),
            PluginDigest::from_bytes([1; 32]),
            PluginGeneration::INITIAL,
        );
        let terminal_evidence = PluginTerminalEvidence::certified(&terminal_active);
        let terminal = terminal_active
            .begin_draining()
            .unwrap()
            .terminal(terminal_evidence)
            .unwrap();
        let uncertain = active_snapshot(
            PluginActivationId::new("history-uncertain").unwrap(),
            PluginDigest::from_bytes([1; 32]),
            PluginGeneration::INITIAL,
        )
        .begin_draining()
        .unwrap()
        .uncertain()
        .unwrap();

        for snapshot in [
            stale_generation,
            start_intent_unavailable,
            backend_unavailable,
            rejected,
            response_lost,
            negotiation_failed,
            ready_cas_failed,
            active,
            draining,
            terminal,
            uncertain,
        ] {
            assert_eq!(
                snapshot.transition_history().last(),
                Some(&snapshot.state())
            );
        }
    }

    #[test]
    fn proven_backend_unavailability_reaches_start_and_remains_not_started() {
        let mut process = UnavailableProcess::default();
        let snapshot = request().activate_with_reservation(
            &mut process,
            &mut Transport::new(vec![]),
            &Generation::current(),
            &Starts,
        );
        assert_eq!(snapshot.state(), ActivationState::Verified);
        assert_eq!(process.calls, 1);
        assert_eq!(snapshot.transition_history(), [ActivationState::Verified]);
        assert_eq!(
            snapshot.attempt_receipts(),
            [
                PluginActivationReceipt::StartAttempted,
                PluginActivationReceipt::StartProvenNotStarted,
            ]
        );
        assert!(snapshot.start_intent.is_none());
        assert!(snapshot.generation_lease.is_none());
    }

    #[test]
    fn rejected_start_remains_verified_with_proven_not_started_receipt() {
        let mut process = RejectedProcess::default();
        let snapshot = request().activate_with_reservation(
            &mut process,
            &mut Transport::new(vec![]),
            &Generation::current(),
            &Starts,
        );
        assert_eq!(snapshot.state(), ActivationState::Verified);
        assert_eq!(process.calls, 1);
        assert_eq!(snapshot.transition_history(), [ActivationState::Verified]);
        assert_eq!(
            snapshot.attempt_receipts(),
            [
                PluginActivationReceipt::StartAttempted,
                PluginActivationReceipt::StartProvenNotStarted,
            ]
        );
    }

    #[test]
    fn lost_start_response_retains_start_intent_and_generation_lease_for_reconciliation() {
        let mut process = LostResponseProcess::default();
        let snapshot = request().activate_with_reservation(
            &mut process,
            &mut Transport::new(vec![]),
            &Generation::current(),
            &Starts,
        );
        assert_eq!(snapshot.state(), ActivationState::Uncertain);
        assert_eq!(process.calls, 1);
        assert_eq!(
            snapshot.transition_history(),
            [
                ActivationState::Verified,
                ActivationState::Starting,
                ActivationState::Uncertain,
            ]
        );
        assert!(snapshot.start_intent.is_some());
        assert!(snapshot.generation_lease.is_some());
        assert!(snapshot.process_lease.is_none());
    }

    #[test]
    fn mismatched_start_reservation_is_uncertain_after_process_boundary() {
        let request = request();
        let mut process = WrongReservationProcess::default();
        let snapshot = request.activate_with_reservation(
            &mut process,
            &mut Transport::new(vec![]),
            &Generation::current(),
            &Starts,
        );
        assert_eq!(snapshot.state(), ActivationState::Uncertain);
        assert_eq!(process.calls, 1);
        assert!(snapshot.start_intent.is_some());
        assert!(snapshot.generation_lease.is_some());
        assert!(snapshot.process_lease.is_none());
    }

    #[derive(Default)]
    struct Process {
        calls: usize,
    }
    impl PluginProcessPort for Process {
        fn start(
            &mut self,
            intent: &PluginStartIntent,
            _: &PluginGenerationReadLease,
        ) -> Result<PluginProcessLease, PluginProcessPortError> {
            self.calls += 1;
            Ok(PluginProcessLease::certified(intent))
        }
    }
    #[derive(Default)]
    struct UnavailableProcess {
        calls: usize,
    }
    impl PluginProcessPort for UnavailableProcess {
        fn start(
            &mut self,
            _: &PluginStartIntent,
            _: &PluginGenerationReadLease,
        ) -> Result<PluginProcessLease, PluginProcessPortError> {
            self.calls += 1;
            Err(PluginProcessPortError::BackendUnavailable)
        }
    }
    #[derive(Default)]
    struct LostResponseProcess {
        calls: usize,
    }
    #[derive(Default)]
    struct RejectedProcess {
        calls: usize,
    }
    impl PluginProcessPort for RejectedProcess {
        fn start(
            &mut self,
            _: &PluginStartIntent,
            _: &PluginGenerationReadLease,
        ) -> Result<PluginProcessLease, PluginProcessPortError> {
            self.calls += 1;
            Err(PluginProcessPortError::Rejected)
        }
    }
    impl PluginProcessPort for LostResponseProcess {
        fn start(
            &mut self,
            _: &PluginStartIntent,
            _: &PluginGenerationReadLease,
        ) -> Result<PluginProcessLease, PluginProcessPortError> {
            self.calls += 1;
            Err(PluginProcessPortError::ResponseLost)
        }
    }
    #[derive(Default)]
    struct WrongReservationProcess {
        calls: usize,
    }
    impl PluginProcessPort for WrongReservationProcess {
        fn start(
            &mut self,
            _: &PluginStartIntent,
            _: &PluginGenerationReadLease,
        ) -> Result<PluginProcessLease, PluginProcessPortError> {
            self.calls += 1;
            let wrong = PluginStartIntent::issued(
                PluginActivationId::new("wrong-reservation").unwrap(),
                PluginDigest::from_bytes([7; 32]),
                PluginGeneration::INITIAL,
                [9; 32],
            );
            Ok(PluginProcessLease::certified(&wrong))
        }
    }
    struct Generation {
        fail_ready: bool,
        generation: PluginGeneration,
    }
    /// Test-only stand-in for a durable authority. Its fixed epoch is part of
    /// the fixture identity, so a reconstructed fixture with another epoch
    /// cannot recreate a reservation accepted by an earlier one.
    struct Starts;
    impl PluginStartIntentPort for Starts {
        fn reserve(
            &self,
            activation_id: &PluginActivationId,
            package_digest: PluginDigest,
            generation: PluginGeneration,
        ) -> Result<PluginStartIntent, crate::PluginStartIntentPortError> {
            let mut reservation = [0; 32];
            reservation[..8].copy_from_slice(&generation.get().to_be_bytes());
            reservation[8..].copy_from_slice(&package_digest.as_bytes()[..24]);
            Ok(PluginStartIntent::issued(
                activation_id.clone(),
                package_digest,
                generation,
                reservation,
            ))
        }
    }
    struct UnavailableStarts;
    impl PluginStartIntentPort for UnavailableStarts {
        fn reserve(
            &self,
            _: &PluginActivationId,
            _: PluginDigest,
            _: PluginGeneration,
        ) -> Result<PluginStartIntent, crate::PluginStartIntentPortError> {
            Err(crate::PluginStartIntentPortError::Unavailable)
        }
    }
    impl Generation {
        fn current() -> Self {
            Self::at(PluginGeneration::INITIAL)
        }
        fn at(generation: PluginGeneration) -> Self {
            Self {
                fail_ready: false,
                generation,
            }
        }
    }
    impl PluginGenerationPort for Generation {
        fn acquire_read_lease(
            &self,
            id: &PluginActivationId,
        ) -> Result<PluginGenerationReadLease, PluginGenerationPortError> {
            Ok(PluginGenerationReadLease::issued(
                id.clone(),
                self.generation,
            ))
        }
        fn ready_compare_and_set(
            &self,
            _: &PluginGenerationReadLease,
        ) -> Result<(), PluginGenerationPortError> {
            if self.fail_ready {
                Err(PluginGenerationPortError::Unavailable)
            } else {
                Ok(())
            }
        }
    }
    struct Transport {
        frames: Vec<BootstrapMessage>,
        oversized: bool,
    }

    struct CountingProcess {
        start_calls: usize,
        result: ResultKind,
    }

    enum ResultKind {
        Success,
        BackendUnavailable,
    }

    impl CountingProcess {
        fn success() -> Self {
            Self {
                start_calls: 0,
                result: ResultKind::Success,
            }
        }

        fn backend_unavailable() -> Self {
            Self {
                start_calls: 0,
                result: ResultKind::BackendUnavailable,
            }
        }
    }

    impl PluginProcessPort for CountingProcess {
        fn start(
            &mut self,
            intent: &PluginStartIntent,
            _: &PluginGenerationReadLease,
        ) -> Result<PluginProcessLease, PluginProcessPortError> {
            self.start_calls += 1;
            match self.result {
                ResultKind::Success => Ok(PluginProcessLease::certified(intent)),
                ResultKind::BackendUnavailable => Err(PluginProcessPortError::BackendUnavailable),
            }
        }
    }

    struct CountingGeneration {
        fail_ready: bool,
        generation: PluginGeneration,
        ready_cas_calls: Cell<usize>,
    }

    trait ReadyCasCounter {
        fn ready_cas_calls(&self) -> usize;
    }

    impl ReadyCasCounter for CountingGeneration {
        fn ready_cas_calls(&self) -> usize {
            self.ready_cas_calls.get()
        }
    }

    impl CountingGeneration {
        fn current() -> Self {
            Self::at(PluginGeneration::INITIAL)
        }

        fn at(generation: PluginGeneration) -> Self {
            Self {
                fail_ready: false,
                generation,
                ready_cas_calls: Cell::new(0),
            }
        }

        fn failing_ready() -> Self {
            Self {
                fail_ready: true,
                ..Self::current()
            }
        }
    }

    impl PluginGenerationPort for CountingGeneration {
        fn acquire_read_lease(
            &self,
            id: &PluginActivationId,
        ) -> Result<PluginGenerationReadLease, PluginGenerationPortError> {
            Ok(PluginGenerationReadLease::issued(
                id.clone(),
                self.generation,
            ))
        }

        fn ready_compare_and_set(
            &self,
            _: &PluginGenerationReadLease,
        ) -> Result<(), PluginGenerationPortError> {
            self.ready_cas_calls.set(self.ready_cas_calls.get() + 1);
            if self.fail_ready {
                Err(PluginGenerationPortError::Unavailable)
            } else {
                Ok(())
            }
        }
    }

    struct CountingRegistry<'a> {
        registry: &'a PluginAuthorityRegistry,
        ready_cas_calls: Cell<usize>,
    }

    impl<'a> CountingRegistry<'a> {
        fn new(registry: &'a PluginAuthorityRegistry) -> Self {
            Self {
                registry,
                ready_cas_calls: Cell::new(0),
            }
        }
    }

    impl PluginGenerationPort for CountingRegistry<'_> {
        fn acquire_read_lease(
            &self,
            id: &PluginActivationId,
        ) -> Result<PluginGenerationReadLease, PluginGenerationPortError> {
            self.registry.acquire_read_lease(id)
        }

        fn ready_compare_and_set(
            &self,
            lease: &PluginGenerationReadLease,
        ) -> Result<(), PluginGenerationPortError> {
            self.ready_cas_calls.set(self.ready_cas_calls.get() + 1);
            self.registry.ready_compare_and_set(lease)
        }
    }

    impl ReadyCasCounter for CountingRegistry<'_> {
        fn ready_cas_calls(&self) -> usize {
            self.ready_cas_calls.get()
        }
    }

    enum WireResponse {
        V1(BootstrapMessage),
        V2(SelectionAcknowledgedV2),
        Oversized,
    }

    struct CountingTransport {
        responses: Vec<WireResponse>,
        write_calls: usize,
        read_calls: usize,
    }

    impl CountingTransport {
        fn new(responses: Vec<WireResponse>) -> Self {
            Self {
                responses,
                write_calls: 0,
                read_calls: 0,
            }
        }

        fn oversized() -> Self {
            Self::new(vec![WireResponse::Oversized])
        }
    }

    impl PluginTransportPort for CountingTransport {
        fn send(&mut self, outbound: PluginBootstrapFrame) -> Result<(), PluginTransportPortError> {
            self.write_calls += 1;
            assert!(!outbound.as_bytes().is_empty());
            Ok(())
        }

        fn receive(&mut self, inbound: &mut [u8]) -> Result<usize, PluginTransportPortError> {
            let response = self.responses.remove(0);
            self.read_calls += 1;
            match response {
                WireResponse::Oversized => Ok(inbound.len() + 1),
                WireResponse::V1(message) => {
                    let frame = encode_frame(
                        &message,
                        &FrameLimits {
                            max_frame_bytes: MAX_BOOTSTRAP_FRAME_BYTES,
                        },
                    )
                    .unwrap();
                    inbound[..frame.len()].copy_from_slice(&frame);
                    Ok(frame.len())
                }
                WireResponse::V2(ack) => {
                    let frame = gocode_plugin_protocol::frame::encode_codec_frame(
                        &ack,
                        &FrameLimits {
                            max_frame_bytes: MAX_BOOTSTRAP_FRAME_BYTES,
                        },
                    )
                    .unwrap();
                    inbound[..frame.len()].copy_from_slice(&frame);
                    Ok(frame.len())
                }
            }
        }
    }

    fn peer_hello(request: &PluginActivationRequest) -> PluginHello {
        let metadata = request.package.plugin_hello_metadata();
        PluginHello {
            host_nonce: request.host_nonce(),
            plugin_nonce: Nonce::from_bytes([2; 16]),
            host_identity: metadata.host_identity,
            package_id: metadata.package_id,
            package_digest: PackageDigest::new(
                DigestAlgorithm::Sha256,
                *request.package_digest().as_bytes(),
            ),
            package_version: metadata.package_version,
            manifest_digest: metadata.manifest_digest,
            plugin_identity: metadata.plugin_identity,
            target_identity: metadata.target_identity,
            entrypoint: metadata.entrypoint,
            supported_profiles: request.package.advertised_profiles(),
        }
    }

    fn exact_v2_transport(request: &PluginActivationRequest) -> CountingTransport {
        let profile = request.protocol_profile();
        CountingTransport::new(vec![
            WireResponse::V1(BootstrapMessage::PluginHello(peer_hello(request))),
            WireResponse::V2(SelectionAcknowledgedV2 {
                host_nonce: request.host_nonce(),
                plugin_nonce: Nonce::from_bytes([2; 16]),
                session_id: request.session_id(),
                profile_id: profile.profile_id().clone(),
                profile_digest: *profile.profile_digest(),
            }),
        ])
    }
    impl Transport {
        fn new(frames: Vec<BootstrapMessage>) -> Self {
            Self {
                frames,
                oversized: false,
            }
        }
        fn oversized() -> Self {
            Self {
                frames: vec![],
                oversized: true,
            }
        }
    }
    impl PluginTransportPort for Transport {
        fn send(&mut self, outbound: PluginBootstrapFrame) -> Result<(), PluginTransportPortError> {
            assert!(!outbound.as_bytes().is_empty());
            Ok(())
        }

        fn receive(&mut self, inbound: &mut [u8]) -> Result<usize, PluginTransportPortError> {
            if self.oversized {
                return Ok(inbound.len() + 1);
            }
            let response = self.frames.remove(0);
            let frame = match response {
                BootstrapMessage::SelectionAcknowledged(value) => {
                    gocode_plugin_protocol::frame::encode_codec_frame(
                        &SelectionAcknowledgedV2 {
                            host_nonce: value.host_nonce,
                            plugin_nonce: value.plugin_nonce,
                            session_id: value.session_id,
                            profile_id: value.profile_id,
                            profile_digest: value.profile_digest,
                        },
                        &FrameLimits {
                            max_frame_bytes: MAX_BOOTSTRAP_FRAME_BYTES,
                        },
                    )
                    .unwrap()
                }
                other => encode_frame(
                    &other,
                    &FrameLimits {
                        max_frame_bytes: MAX_BOOTSTRAP_FRAME_BYTES,
                    },
                )
                .unwrap(),
            };
            inbound[..frame.len()].copy_from_slice(&frame);
            Ok(frame.len())
        }
    }
}
