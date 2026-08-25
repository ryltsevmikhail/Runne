use super::*;
use runne_api::{ApiActor, ApiPrincipalId, ProcessCommandContext, ProcessQueryContext};
use runne_domain::id::{
    AttemptId, CommandId, IdempotencyKey, InvocationId, TaskRunId, WorkspaceId,
};
use runne_application::ports::RuntimeAuthorityId;
use runne_security::SecretBroker;
use runne_store::store::StoreTransaction;
use runne_store::store::process::{DurableProcessOutput, DurableProcessRecord};
use std::sync::Arc;
use tempfile::TempDir;

fn command() -> StartProcessCommand {
    StartProcessCommand {
        workspace_id: WorkspaceId::from_bytes([7; 16]),
        task_run_id: TaskRunId::from_bytes([7; 16]),
        attempt_id: AttemptId::from_bytes([7; 16]),
        invocation_id: InvocationId::from_bytes([7; 16]),
    }
}

fn context(principal: &str) -> ProcessCommandContext {
    ProcessCommandContext {
        command_id: CommandId::from_bytes([7; 16]),
        idempotency_key: IdempotencyKey::new("process-test").expect("valid key"),
        principal: ApiPrincipalId::new(principal).expect("valid principal"),
        actor: ApiActor::new("desktop-test").expect("valid actor"),
    }
}

fn provider() -> (TempDir, NativeProcessProvider<UnavailableProcessInvocationResolver>) {
    let directory = TempDir::new().expect("temporary process store");
    let store_directory = directory.path().join("runne-daemon");
    std::fs::create_dir(&store_directory).expect("store directory");
    let store_path = store_directory.join("event-log.sqlite");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(
            directory.path(),
            std::fs::Permissions::from_mode(0o700),
        )
        .expect("temporary permissions");
        std::fs::set_permissions(
            &store_directory,
            std::fs::Permissions::from_mode(0o700),
        )
        .expect("store permissions");
    }
    let store = StoreTransaction::open(
        &store_path.to_string_lossy(),
        RuntimeAuthorityId("test-host".into()),
        Arc::new(SecretBroker::new().prohibited_content_guard()),
    )
    .expect("process store");
    (
        directory,
        NativeProcessProvider::new(
            UnavailableProcessInvocationResolver,
            RootAdmissionGateway::unavailable(),
            store,
        ),
    )
}

#[test]
fn rejects_non_owner_before_resolver_access() {
    let (_directory, provider) = provider();
    assert_eq!(
        provider.start_process(&context("other"), &command()),
        Err(ProcessHostError::Forbidden)
    );
}

#[test]
fn composed_provider_stays_unavailable_without_authoritative_invocation() {
    let (_directory, provider) = provider();
    assert_eq!(
        provider.start_process(&context(OWNER_PRINCIPAL), &command()),
        Err(ProcessHostError::Unavailable)
    );
}

#[test]
fn authoritative_invocation_registry_requires_exact_runtime_registration() {
    let registry = AuthoritativeProcessInvocationRegistry::default();
    let registered = command();
    let resolved = test_resolved_invocation([4; 32]);
    registry
        .register(registered, resolved.clone())
        .expect("first runtime registration");

    assert_eq!(registry.resolve(&registered).expect("exact invocation").request_digest, [4; 32]);
    assert!(matches!(
        registry.resolve(&StartProcessCommand {
            invocation_id: InvocationId::from_bytes([8; 16]),
            ..registered
        }),
        Err(ProcessHostError::Unavailable)
    ));
    assert_eq!(
        registry.register(registered, test_resolved_invocation([5; 32])),
        Err(ProcessInvocationRegistrationError::Conflict)
    );
}

fn test_resolved_invocation(request_digest: [u8; 32]) -> ResolvedProcessInvocation {
    use runne_platform::{
        containment::{ContainmentBackendId, ContainmentBackendVersion, ContainmentGate, HostPlatform, RunnerIdentity},
    };
    use runne_platform_ports::process::{
        HeldProcessTreeHandleV1, ProcessAttemptIdV1, ProcessGenerationIdV1,
        ProcessOwnerIdV1, ProcessSessionIdV1,
    };
    use runne_security::broker::process::{CommandPolicy, ProcessSpec};
    use std::collections::HashMap;

    ResolvedProcessInvocation {
        request_digest,
        spec: ProcessSpec {
            executable: "/opt/runne/bin/tool".into(),
            executable_digest: Some([9; 32]),
            argv: vec!["--check".into()],
            env: HashMap::new(),
            allowed_env_keys: Vec::new(),
            inherit_environment: false,
            cwd: "/workspace".into(),
            authorized_cwd: Some("/workspace".into()),
            cleanup_reservation_id: Some("cleanup".into()),
            worker_generation: 1,
            expected_generation: 1,
            timeout_ms: 1_000,
            command_policy: CommandPolicy::StructuredOnly,
        },
        executable_relative: "bin/tool".into(),
        cwd_relative: ".".into(),
        binding: ProcessLifecycleBindingV1::new(
            ProcessOwnerIdV1::new([1; 16]).unwrap(),
            ProcessAttemptIdV1::new([2; 16]).unwrap(),
            ProcessSessionIdV1::new([3; 16]).unwrap(),
            ProcessGenerationIdV1::new([4; 16]).unwrap(),
            HeldProcessTreeHandleV1::new([5; 16]).unwrap(),
        ),
        containment: ContainmentRequest::new(
            ContainmentBackendId::new("test").unwrap(),
            ContainmentBackendVersion::new("1").unwrap(),
            HostPlatform::Linux,
            RunnerIdentity::new("test-runner").unwrap(),
            vec![ContainmentGate::WorkspaceFilesystemConfined],
        )
        .unwrap(),
        certificate: None,
        probes: Vec::new(),
    }
}

#[test]
fn terminal_process_and_output_are_read_from_durable_store_after_provider_restart() {
    let (_directory, provider) = provider();
    let process_id = runne_domain::id::ProcessId::from_bytes([9; 16]);
    provider
        .store
        .save_process_record(&DurableProcessRecord {
            process_id: process_id.into_bytes(),
            invocation_id: [8; 16],
            workspace_id: [7; 16],
            task_run_id: [6; 16],
            attempt_id: [5; 16],
            principal_id: OWNER_PRINCIPAL.into(),
            state: 4,
            version: 3,
            next_output_sequence: 2,
            request_digest: [4; 32],
            intent_digest: [5; 32],
            owner_id: [3; 16],
            binding_attempt_id: [2; 16],
            session_id: [1; 16],
            generation_id: [11; 16],
            tree_handle: [12; 16],
            pid: 42,
            start_identity: [13; 32],
            launch_nonce: [14; 16],
        })
        .expect("durable process");
    provider
        .store
        .append_process_output(&DurableProcessOutput {
            process_id: process_id.into_bytes(),
            sequence: 1,
            stream: 1,
            text: "done\n".into(),
        })
        .expect("durable output");

    let snapshot = provider
        .get_process(
            &ProcessQueryContext {
                principal: ApiPrincipalId::new(OWNER_PRINCIPAL).expect("owner"),
            },
            process_id,
        )
        .expect("terminal snapshot");
    assert_eq!(snapshot.state, runne_api::ProcessState::Exited);
    assert_eq!(snapshot.version, 3);
    let page = provider
        .read_process_output(
            &ProcessQueryContext {
                principal: ApiPrincipalId::new(OWNER_PRINCIPAL).expect("owner"),
            },
            process_id,
            0,
            16,
        )
        .expect("durable output page");
    assert_eq!(page.chunks()[0].text(), "done\n");
}
