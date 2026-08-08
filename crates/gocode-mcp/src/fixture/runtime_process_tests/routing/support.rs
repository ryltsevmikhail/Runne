use gocode_tools::{
    ProcessAuthorizationAuthorityV1, ProcessClaimJournalMemoryV1, ProcessContractHostV1,
    ProcessIntentV1, ProcessPlatformTargetV1, ProcessStubDisposition, SandboxQualificationProbe,
    ToolOutputBounds,
};
use serde_json::json;
use std::sync::Arc;
mod advance;
mod fixture;
mod material;
mod mixed;
use super::super::super::process::FixtureProcessComposition;
use super::super::super::runtime::FixtureProcessApprovalAuthority;
use super::super::super::{
    FixtureApproval, FixtureApprovalPolicy, FixtureAuditProcessPhase, FixtureCallCapability,
    FixtureIdentity, FixtureInitialize, FixtureLimits, FixtureMcpMode, FixtureMcpRuntime,
    FixturePublication, FixtureScript, FixtureStep, FixtureTool,
};
use super::super::super::{
    process_gateway::McpProcessToolGateway,
    runtime::process_ledger::{ProcessPhaseOutcome, ProcessPreEffectFailure, ProcessRefundReason},
};
use crate::fixture::process_gateway::ProcessGateFault;
use crate::{McpConnectionId, McpRuntimeInstanceId, McpServerId, McpSessionId};
use advance::AdvanceAuthorizationProbe;
pub(in crate::fixture) use fixture::protocol_fixture;
use fixture::{identity, initialize, process_tool, script};
use material::{authority, intent};
pub(in crate::fixture) use mixed::assert_protocol_process_invocation_conflicts;

pub(in crate::fixture) enum Probe {
    Production,
    Qualified,
    AdvanceAuthorization,
    Controlled(Arc<dyn SandboxQualificationProbe>),
}

struct QualifiedProbe;

impl SandboxQualificationProbe for QualifiedProbe {
    fn qualify(&self) -> Result<(), ProcessStubDisposition> {
        Ok(())
    }
}

pub(in crate::fixture) struct Ready {
    pub(in crate::fixture) runtime: FixtureMcpRuntime,
    authority: FixtureProcessApprovalAuthority,
    publication: FixturePublication,
    raw_authority: ProcessAuthorizationAuthorityV1,
}

impl Ready {
    pub(in crate::fixture) fn intent(&self, invocation: &str) -> ProcessIntentV1 {
        intent(&self.publication.binding, invocation)
    }

    pub(in crate::fixture) fn issue(&self, invocation: &str) -> FixtureCallCapability {
        self.publication
            .issue_process_dispatch_for_test(
                "process",
                invocation,
                json!({}),
                self.intent(invocation),
                &self.authority,
                20,
                10,
            )
            .unwrap()
    }

    pub(in crate::fixture) fn issue_from(
        &self,
        publication: &FixturePublication,
        invocation: &str,
    ) -> FixtureCallCapability {
        publication
            .issue_process_dispatch_for_test(
                "process",
                invocation,
                json!({}),
                intent(&publication.binding, invocation),
                &self.authority,
                20,
                10,
            )
            .unwrap()
    }

    pub(in crate::fixture) fn issue_protocol(&self, invocation: &str) -> FixtureCallCapability {
        self.publication
            .issue_dispatch(
                "protocol",
                invocation,
                json!({}),
                "principal",
                "authority",
                20,
            )
            .unwrap()
    }
}

pub(in crate::fixture) fn ready(probe: Probe, limit: u64, policy: FixtureApprovalPolicy) -> Ready {
    let authority = authority();
    let host = ProcessContractHostV1::new(
        ProcessClaimJournalMemoryV1::new(),
        ProcessPlatformTargetV1::Linux,
        100,
    );
    let composition = match probe {
        Probe::Production => FixtureProcessComposition::new(authority.clone(), host),
        Probe::Qualified => FixtureProcessComposition::new_with_probe(
            authority.clone(),
            host,
            Arc::new(QualifiedProbe),
        ),
        Probe::AdvanceAuthorization => FixtureProcessComposition::new_with_probe(
            authority.clone(),
            host,
            Arc::new(AdvanceAuthorizationProbe::new(authority.clone())),
        ),
        Probe::Controlled(probe) => {
            FixtureProcessComposition::new_with_probe(authority.clone(), host, probe)
        }
    };
    let (mut runtime, _, process_authority) = FixtureMcpRuntime::new_with_process_authorities(
        FixtureMcpMode::FixtureOnly,
        identity(),
        vec![process_tool()],
        script(),
        &["process"],
        FixtureLimits::default(),
        policy,
        limit,
        composition,
    )
    .unwrap();
    initialize(&mut runtime, "connection-1", 1);
    let publication = runtime.discover().unwrap();
    Ready {
        runtime,
        authority: process_authority,
        publication,
        raw_authority: authority,
    }
}

pub(in crate::fixture) fn ready_without_composition(
    limit: u64,
    policy: FixtureApprovalPolicy,
) -> Ready {
    let raw_authority = authority();
    let authority = FixtureProcessApprovalAuthority::new(raw_authority.clone());
    let mut runtime = FixtureMcpRuntime::new(
        FixtureMcpMode::FixtureOnly,
        identity(),
        vec![process_tool()],
        script(),
        &["process"],
        FixtureLimits::default(),
        policy,
        limit,
    )
    .unwrap();
    initialize(&mut runtime, "connection-1", 1);
    let publication = runtime.discover().unwrap();
    Ready {
        runtime,
        authority,
        publication,
        raw_authority,
    }
}

pub(in crate::fixture) fn key_payload(
    fixture: &Ready,
    invocation: &str,
) -> (
    super::super::super::process_call::ProcessEffectKey,
    super::super::super::process_call::ProcessDispatchPayload,
) {
    let mut capability = fixture.issue(invocation);
    (
        capability.process_key().unwrap().clone(),
        capability.take_process_payload().unwrap(),
    )
}
pub(in crate::fixture) fn budget_denied_dispatch(
    fixture: &Ready,
    invocation: &str,
) -> super::super::super::process_call::ProcessDispatchPayload {
    let (key, payload) = key_payload(fixture, invocation);
    match test_gateway(fixture, ProcessGateFault::BudgetDenied)
        .dispatch_for_test(&fixture.runtime, key, payload)
        .unwrap()
    {
        ProcessPhaseOutcome::PreEffectDenied {
            failure: ProcessPreEffectFailure::Budget,
            receipt,
            payload,
        } => {
            fixture
                .runtime
                .refund_process(receipt, ProcessRefundReason::Budget)
                .unwrap();
            assert_eq!(fixture.runtime.accounting_remaining(), 1);
            *payload
        }
        _ => panic!("expected budget pre-effect denial"),
    }
}
pub(in crate::fixture) fn effect_uncertain_gateway(
    fixture: &Ready,
    fault: ProcessGateFault,
) -> McpProcessToolGateway {
    test_gateway(fixture, fault)
}
fn test_gateway(fixture: &Ready, fault: ProcessGateFault) -> McpProcessToolGateway {
    McpProcessToolGateway::new_with_fault_for_test(
        fixture.raw_authority.clone(),
        ProcessContractHostV1::new(
            ProcessClaimJournalMemoryV1::new(),
            ProcessPlatformTargetV1::Linux,
            100,
        ),
        Arc::new(QualifiedProbe),
        fixture
            .runtime
            .process_generation_authority_for_test()
            .unwrap(),
        Arc::new(fixture.runtime.process_ledger_port()),
        ToolOutputBounds::new(16_384, 64, 64).unwrap(),
        fault,
    )
}
pub(in crate::fixture) fn reconnect(
    runtime: &mut FixtureMcpRuntime,
    connection: &str,
    generation: u64,
) {
    runtime
        .reconnect(McpConnectionId::new(connection).unwrap())
        .unwrap();
    initialize(runtime, connection, generation);
}

pub(in crate::fixture) fn process_phases(
    runtime: &FixtureMcpRuntime,
) -> Vec<FixtureAuditProcessPhase> {
    runtime
        .try_audit()
        .unwrap()
        .into_iter()
        .filter_map(|record| record.process_phase())
        .collect()
}
