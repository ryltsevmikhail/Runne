struct QualifiedProbe;

#[rustfmt::skip]
impl SandboxQualificationProbe for QualifiedProbe { fn qualify(&self) -> Result<(), ProcessStubDisposition> { Ok(()) } }

trait IssueExact {
    fn issue_capability(
        &self,
        intent: &ProcessIntentV1,
        expires_at: u64,
    ) -> Result<ProcessCapabilityV1, ProcessContractError>;
    fn approve(
        &self,
        intent: &ProcessIntentV1,
        expires_at: u64,
        approved: bool,
    ) -> Result<ProcessApprovalV1, ProcessContractError>;
}

impl IssueExact for ProcessAuthorizationAuthorityV1 {
    fn issue_capability(
        &self,
        intent: &ProcessIntentV1,
        expires_at: u64,
    ) -> Result<ProcessCapabilityV1, ProcessContractError> {
        self.bind_call(intent.lifecycle_binding())?
            .issue_capability(intent, expires_at)
    }

    fn approve(
        &self,
        intent: &ProcessIntentV1,
        expires_at: u64,
        approved: bool,
    ) -> Result<ProcessApprovalV1, ProcessContractError> {
        self.bind_call(intent.lifecycle_binding())?
            .approve(intent, expires_at, approved)
    }
}

struct BlockingQualifiedProbe {
    calls: std::sync::atomic::AtomicUsize,
    entered: std::sync::mpsc::Sender<()>,
    release: Mutex<std::sync::mpsc::Receiver<()>>,
}

impl SandboxQualificationProbe for BlockingQualifiedProbe {
    fn qualify(&self) -> Result<(), ProcessStubDisposition> {
        if self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst) == 0 {
            self.entered.send(()).map_err(|_| ProcessStubDisposition::NotQualified)?;
            self.release.lock().unwrap().recv().map_err(|_| ProcessStubDisposition::NotQualified)?;
        }
        Ok(())
    }
}

fn process_id(value: u8) -> [u8; 16] {
    [value; 16]
}

fn binding(g: u64, d: [u8; 32]) -> McpDispatchBinding { McpDispatchBinding::new(McpServerId::new("fixture-server").unwrap(), McpRuntimeInstanceId::new("runtime-1").unwrap(), McpConnectionId::new("connection-1").unwrap(), McpSessionId::new("session-1").unwrap(), g, d).unwrap() }

fn process_context() -> (ProcessAuthorizationAuthorityV1, ProcessIntentV1) {
    process_context_with_command(b"tool")
}

fn process_context_with_command(command: &[u8]) -> (ProcessAuthorizationAuthorityV1, ProcessIntentV1) {
    process_context_with_binding(
        command,
        ProcessIdentityBindingV1::new(
            PrincipalId::new(process_id(7)).unwrap(),
            AuthorityId::new(process_id(8)).unwrap(),
            ProcessOwnerIdV1::new(process_id(9)).unwrap(),
            ProcessAttemptIdV1::new(process_id(10)).unwrap(),
            ProcessSessionIdV1::new(process_id(11)).unwrap(),
            ProcessGenerationIdV1::new(process_id(12)).unwrap(),
            CapabilityGrantId::new(process_id(13)).unwrap(),
            SandboxId::new(process_id(14)).unwrap(),
            HeldProcessTreeHandleV1::new(process_id(15)).unwrap(),
        ),
        1,
        4,
    )
}

fn process_context_for(
    binding: &McpDispatchBinding,
    invocation: &McpInvocationId,
) -> (ProcessAuthorizationAuthorityV1, ProcessIntentV1) {
    process_context_with_material(binding, invocation, b"tool", 1, 4)
}

fn process_context_with_material(
    binding: &McpDispatchBinding,
    invocation: &McpInvocationId,
    command: &[u8],
    executable_seed: u8,
    cwd_seed: u8,
) -> (ProcessAuthorizationAuthorityV1, ProcessIntentV1) {
    process_context_with_binding(
        command,
        derive_process_identity_binding(
            binding,
            invocation,
            PrincipalId::new(process_id(7)).unwrap(),
            AuthorityId::new(process_id(8)).unwrap(),
            CapabilityGrantId::new(process_id(13)).unwrap(),
            SandboxId::new(process_id(14)).unwrap(),
        ),
        executable_seed,
        cwd_seed,
    )
}

fn process_context_with_binding(
    command: &[u8],
    binding: ProcessIdentityBindingV1,
    executable_seed: u8,
    cwd_seed: u8,
) -> (ProcessAuthorizationAuthorityV1, ProcessIntentV1) {
    let file = |value| {
        HeldFileIdentityV1::new(
            process_id(value),
            [value; 32],
            [value + 1; 32],
            [value + 2; 32],
            1,
        )
        .unwrap()
    };
    let executable = VerifiedExecutableV1::new(
        file(executable_seed),
        ProcessFileKindV1::RegularFile,
        ProcessSymlinkProofV1::VerifiedNotSymlink,
    )
    .unwrap();
    let cwd = VerifiedCwdV1::new(
        file(cwd_seed),
        ProcessFileKindV1::Directory,
        ProcessSymlinkProofV1::VerifiedNotSymlink,
    )
    .unwrap();
    let policy = ExecutablePolicyId::new(process_id(16)).unwrap();
    let root = AllowedRootId::new(process_id(17)).unwrap();
    let intent = ProcessIntentV1::new(
        ApprovalId::new(process_id(18)).unwrap(),
        executable.clone(),
        policy.clone(),
        cwd.clone(),
        root.clone(),
        BoundedArgvV1::new(
            vec![PortableUtf8V1::from_bytes(command.to_vec()).unwrap()],
            InputBoundsV1::new(1, 4, 4).unwrap(),
        )
        .unwrap(),
        ExplicitEnvironmentV1::empty(),
        StdinPolicyV1::closed(),
        ProcessIoBoundsV1::new(4, 4, 8, 3, true).unwrap(),
        binding.clone(),
    )
    .unwrap();
    (
        ProcessAuthorizationAuthorityV1::new(
            executable,
            policy,
            cwd,
            root,
            PrincipalId::new(process_id(7)).unwrap(),
            AuthorityId::new(process_id(8)).unwrap(),
            CapabilityGrantId::new(process_id(13)).unwrap(),
            SandboxId::new(process_id(14)).unwrap(),
            ApproverId::new(process_id(19)).unwrap(),
            1,
            1,
            process_id(20),
        )
        .unwrap(),
        intent,
    )
}

fn process_gateway(
    authority: ProcessAuthorizationAuthorityV1,
    probe: Arc<dyn SandboxQualificationProbe>,
    generation: Arc<McpGenerationAuthority>,
) -> McpProcessToolGateway {
    process_gateway_with_clock(authority, probe, generation, 100)
}

fn process_gateway_with_clock(
    authority: ProcessAuthorizationAuthorityV1,
    probe: Arc<dyn SandboxQualificationProbe>,
    generation: Arc<McpGenerationAuthority>,
    clock_seed: u64,
) -> McpProcessToolGateway {
    let host = ProcessContractHostV1::new(
        ProcessClaimJournalMemoryV1::new(),
        ProcessPlatformTargetV1::Linux,
        clock_seed,
    );
    let mut composition = FixtureProcessComposition::new_with_probe(authority, host, probe);
    composition
        .compose_gateway(
            generation,
            ToolOutputBounds::new(1024, 16, 16).unwrap(),
        )
        .expect("fixture process composition must compose one gateway")
}

fn publication(class: McpToolExecutionClass) -> PublishedMcpTools {
    publish_mcp_tools(
        McpServerId::new("fixture-server").unwrap(),
        McpServerKind::Local,
        vec![McpToolDescriptor::new_with_execution_class("process", "1.0.0", json!({"type":"object"}), class).unwrap()],
        &["process"],
    )
    .unwrap()
}

fn process_call(
    capability: McpToolDispatchCapability,
    intent: ProcessIntentV1,
    process_capability: ProcessCapabilityV1,
    approval: ProcessApprovalV1,
) -> McpProcessCall {
    McpProcessCall::new(capability, intent, process_capability, approval, 10)
}
