use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use super::*;
use runne_platform_ports::process::{
    HeldProcessTreeHandleV1, ProcessAttemptIdV1, ProcessGenerationIdV1, ProcessLifecycleBindingV1,
    ProcessOwnerIdV1, ProcessSessionIdV1,
};

#[derive(Clone, Default)]
struct RecordingLauncher {
    launches: Arc<Mutex<Vec<[u8; 16]>>>,
    stops: Arc<Mutex<Vec<OwnedProcessHandleV1>>>,
}

impl OwnerBoundProcessLauncher for RecordingLauncher {
    fn launch(
        &self,
        request: &OwnerBoundProcessLaunchRequest<'_>,
    ) -> Result<ProcessLaunchObservationV1, OwnerBoundProcessError> {
        self.launches
            .lock()
            .expect("launch lock")
            .push(*request.launch_nonce());
        ProcessLaunchObservationV1::new(41, [7; 32])
    }

    fn stop(&self, handle: &OwnedProcessHandleV1) -> Result<(), OwnerBoundProcessError> {
        self.stops.lock().expect("stop lock").push(handle.clone());
        Ok(())
    }
}

struct FailingLauncher;

impl OwnerBoundProcessLauncher for FailingLauncher {
    fn launch(
        &self,
        _: &OwnerBoundProcessLaunchRequest<'_>,
    ) -> Result<ProcessLaunchObservationV1, OwnerBoundProcessError> {
        Err(OwnerBoundProcessError::LifecycleRejected)
    }

    fn stop(&self, _: &OwnedProcessHandleV1) -> Result<(), OwnerBoundProcessError> {
        Err(OwnerBoundProcessError::LifecycleRejected)
    }
}

struct StopFailingLauncher;

impl OwnerBoundProcessLauncher for StopFailingLauncher {
    fn launch(
        &self,
        _: &OwnerBoundProcessLaunchRequest<'_>,
    ) -> Result<ProcessLaunchObservationV1, OwnerBoundProcessError> {
        ProcessLaunchObservationV1::new(42, [8; 32])
    }

    fn stop(&self, _: &OwnedProcessHandleV1) -> Result<(), OwnerBoundProcessError> {
        Err(OwnerBoundProcessError::LifecycleRejected)
    }
}

fn binding(value: u8) -> ProcessLifecycleBindingV1 {
    ProcessLifecycleBindingV1::new(
        ProcessOwnerIdV1::new([value; 16]).expect("owner"),
        ProcessAttemptIdV1::new([value + 1; 16]).expect("attempt"),
        ProcessSessionIdV1::new([value + 2; 16]).expect("session"),
        ProcessGenerationIdV1::new([value + 3; 16]).expect("generation"),
        HeldProcessTreeHandleV1::new([value + 4; 16]).expect("tree"),
    )
}

fn spec() -> ProcessSpec {
    let cwd = "/virtual/workspace".to_owned();
    ProcessSpec {
        executable: "/virtual/bin/tool".into(),
        executable_digest: Some([1; 32]),
        argv: vec!["--version".into()],
        env: HashMap::new(),
        allowed_env_keys: Vec::new(),
        inherit_environment: false,
        cwd: cwd.clone(),
        authorized_cwd: Some(cwd),
        cleanup_reservation_id: Some("cleanup-1".into()),
        worker_generation: 1,
        expected_generation: 1,
        timeout_ms: 1_000,
        command_policy: CommandPolicy::StructuredOnly,
    }
}

fn invocation(value: u8) -> ProcessInvocationIdV1 {
    ProcessInvocationIdV1::new([value; 16]).expect("invocation")
}

#[test]
fn owner_bound_launch_returns_pid_start_identity_and_single_use_nonce() {
    let broker = ProcessBroker::new(CommandPolicy::StructuredOnly);
    let launcher = RecordingLauncher::default();
    let handle = broker
        .launch_owner_bound_after_admission(
            OwnerBoundProcessRequest::new(spec(), binding(1), invocation(9)),
            &launcher,
        )
        .expect("launch");

    assert_eq!(handle.pid(), 41);
    assert_eq!(handle.start_identity(), &[7; 32]);
    assert_ne!(handle.launch_nonce(), &[0; 16]);
    assert_eq!(launcher.launches.lock().expect("launches").len(), 1);

    broker
        .stop_owner_bound(binding(1), invocation(9), handle, &launcher)
        .expect("stop");
    assert_eq!(launcher.stops.lock().expect("stops").len(), 1);
}

#[test]
fn owner_mismatch_and_replayed_stop_are_rejected_without_second_stop() {
    let broker = ProcessBroker::new(CommandPolicy::StructuredOnly);
    let launcher = RecordingLauncher::default();
    let handle = broker
        .launch_owner_bound_after_admission(
            OwnerBoundProcessRequest::new(spec(), binding(1), invocation(9)),
            &launcher,
        )
        .expect("launch");
    let replay = handle.clone();

    assert_eq!(
        broker.stop_owner_bound(binding(2), invocation(9), handle, &launcher),
        Err(OwnerBoundProcessError::OwnershipMismatch)
    );
    broker
        .stop_owner_bound(binding(1), invocation(9), replay.clone(), &launcher)
        .expect("first stop");
    assert_eq!(
        broker.stop_owner_bound(binding(1), invocation(9), replay, &launcher),
        Err(OwnerBoundProcessError::ProcessAlreadyStopped)
    );
    assert_eq!(launcher.stops.lock().expect("stops").len(), 1);
}

#[test]
fn invocation_identity_is_required_for_owner_bound_stop() {
    let broker = ProcessBroker::new(CommandPolicy::StructuredOnly);
    let launcher = RecordingLauncher::default();
    let request = OwnerBoundProcessRequest::new(
        spec(),
        binding(1),
        ProcessInvocationIdV1::new([9; 16]).expect("invocation"),
    );
    let handle = broker
        .launch_owner_bound_after_admission(request, &launcher)
        .expect("launch");

    assert_eq!(
        broker.stop_owner_bound(
            binding(1),
            ProcessInvocationIdV1::new([8; 16]).expect("invocation"),
            handle,
            &launcher,
        ),
        Err(OwnerBoundProcessError::OwnershipMismatch)
    );
}

#[test]
fn failed_launch_releases_the_reserved_nonce() {
    let broker = ProcessBroker::new(CommandPolicy::StructuredOnly);
    assert_eq!(
        broker.launch_owner_bound_after_admission(
            OwnerBoundProcessRequest::new(spec(), binding(1), invocation(9)),
            &FailingLauncher,
        ),
        Err(OwnerBoundProcessError::LifecycleRejected)
    );
    assert!(broker.owner_bound.lock().expect("registry").is_empty());
}

#[test]
fn duplicate_owner_bound_start_replays_exact_handle_without_second_launch() {
    let broker = ProcessBroker::new(CommandPolicy::StructuredOnly);
    let launcher = RecordingLauncher::default();
    let request = OwnerBoundProcessRequest::new(spec(), binding(1), invocation(9));
    let first = broker
        .launch_owner_bound_after_admission(request, &launcher)
        .expect("first launch");
    let second = broker
        .launch_owner_bound_after_admission(
            OwnerBoundProcessRequest::new(spec(), binding(1), invocation(9)),
            &launcher,
        )
        .expect("replay");
    assert_eq!(first, second);
    assert_eq!(launcher.launches.lock().expect("launches").len(), 1);
}

#[test]
fn duplicate_owner_bound_start_with_changed_intent_is_rejected() {
    let broker = ProcessBroker::new(CommandPolicy::StructuredOnly);
    let launcher = RecordingLauncher::default();
    broker
        .launch_owner_bound_after_admission(
            OwnerBoundProcessRequest::new(spec(), binding(1), invocation(9)),
            &launcher,
        )
        .expect("first launch");
    let mut changed = spec();
    changed.argv.push("--changed".into());
    assert_eq!(
        broker.launch_owner_bound_after_admission(
            OwnerBoundProcessRequest::new(changed, binding(1), invocation(9)),
            &launcher,
        ),
        Err(OwnerBoundProcessError::IntentConflict)
    );
    assert_eq!(launcher.launches.lock().expect("launches").len(), 1);
}

#[test]
fn failed_stop_leaves_an_uncertain_lifecycle_and_blocks_relaunch() {
    let broker = ProcessBroker::new(CommandPolicy::StructuredOnly);
    let launcher = StopFailingLauncher;
    let handle = broker
        .launch_owner_bound_after_admission(
            OwnerBoundProcessRequest::new(spec(), binding(1), invocation(9)),
            &launcher,
        )
        .expect("launch");
    assert_eq!(
        broker.stop_owner_bound(binding(1), invocation(9), handle, &launcher),
        Err(OwnerBoundProcessError::LifecycleRejected)
    );
    assert_eq!(
        broker.launch_owner_bound_after_admission(
            OwnerBoundProcessRequest::new(spec(), binding(1), invocation(9)),
            &launcher,
        ),
        Err(OwnerBoundProcessError::IntentConflict)
    );
}

#[test]
fn durable_owner_bound_adoption_reuses_exact_handle_without_launch() {
    let broker = ProcessBroker::new(CommandPolicy::StructuredOnly);
    let launcher = RecordingLauncher::default();
    let binding = binding(1);
    let invocation = invocation(9);
    let request = OwnerBoundProcessRequest::new(spec(), binding.clone(), invocation);
    let intent_digest = request.intent_digest();
    let handle = OwnedProcessHandleV1::recovered(
        binding.clone(),
        invocation,
        43,
        [9; 32],
        [10; 16],
    )
    .expect("recovered handle");
    broker
        .adopt_owner_bound(binding.clone(), invocation, handle.clone(), intent_digest)
        .expect("adopt");
    let key = OwnerBoundLaunchKey::new(&binding, invocation);
    assert!(matches!(
        broker.owner_bound.lock().expect("registry").get(&key),
        Some(OwnerBoundRegistryEntry::Active {
            intent_digest: existing,
            ..
        }) if existing == &intent_digest
    ));
    assert_eq!(
        broker.adopt_owner_bound(binding.clone(), invocation, handle.clone(), intent_digest),
        Err(OwnerBoundProcessError::IntentConflict)
    );
    broker
        .stop_owner_bound(binding, invocation, handle, &launcher)
        .expect("stop adopted");
    assert_eq!(launcher.stops.lock().expect("stops").len(), 1);
}

#[test]
fn durable_owner_bound_adoption_rejects_missing_intent_digest() {
    let broker = ProcessBroker::new(CommandPolicy::StructuredOnly);
    let binding = binding(1);
    let invocation = invocation(9);
    let handle = OwnedProcessHandleV1::recovered(
        binding.clone(),
        invocation,
        43,
        [9; 32],
        [10; 16],
    )
    .expect("recovered handle");

    assert_eq!(
        broker.adopt_owner_bound(binding, invocation, handle, [0; 32]),
        Err(OwnerBoundProcessError::InvalidIntentDigest)
    );
}
