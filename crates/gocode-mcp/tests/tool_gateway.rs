use std::sync::{Arc, Mutex};

use gocode_mcp::{
    McpClientPort, McpConnectionId, McpDispatchBinding, McpGenerationAdvanceError,
    McpGenerationAuthority, McpInvocationId, McpNormalizedMessage, McpRuntimeInstanceId,
    McpServerId, McpServerKind, McpSessionId, McpToolDescriptor, McpToolGateway,
    McpToolGatewayError, McpTransportError, PublishedMcpTools, publish_mcp_tools,
};
use gocode_tools::{
    EffectAdmission, GateStage, ToolAdmissionDecision, ToolAdmissionError, ToolAdmissionPort,
    ToolClass, ToolDispatchRequest, ToolGatewayError, ToolId, ToolOutputBounds, ToolRef,
};
use serde_json::json;

#[derive(Clone)]
struct Admission {
    calls: Arc<Mutex<Vec<GateStage>>>,
    reject: Option<GateStage>,
}

impl ToolAdmissionPort for Admission {
    fn check(
        &self,
        stage: GateStage,
        _: &ToolDispatchRequest,
    ) -> Result<ToolAdmissionDecision, ToolAdmissionError> {
        self.calls.lock().unwrap().push(stage);
        if self.reject == Some(stage) {
            return Err(ToolAdmissionError::Rejected(stage));
        }
        Ok(if stage == GateStage::EffectAdmission {
            ToolAdmissionDecision::Winner(EffectAdmission {
                permit_id: "mcp-permit".into(),
            })
        } else {
            ToolAdmissionDecision::Passed
        })
    }
}

struct Client {
    sends: Arc<Mutex<usize>>,
    messages: Arc<Mutex<Vec<McpNormalizedMessage>>>,
    fail_after_send: bool,
    generation_cutover: Option<(Arc<McpGenerationAuthority>, McpDispatchBinding)>,
}

impl McpClientPort for Client {
    fn dispatch(&mut self, message: &McpNormalizedMessage) -> Result<(), McpTransportError> {
        *self.sends.lock().unwrap() += 1;
        self.messages.lock().unwrap().push(message.clone());
        if let Some((generation, next_binding)) = &self.generation_cutover {
            assert_eq!(
                generation.try_advance(next_binding),
                Err(McpGenerationAdvanceError::Busy)
            );
        }
        if self.fail_after_send {
            Err(McpTransportError::Unavailable)
        } else {
            Ok(())
        }
    }

    fn receive(&mut self) -> Result<McpNormalizedMessage, McpTransportError> {
        Err(McpTransportError::Unavailable)
    }
}

fn binding(generation: u64, discovery_digest: [u8; 32]) -> McpDispatchBinding {
    McpDispatchBinding::new(
        McpServerId::new("fixture-server").unwrap(),
        McpRuntimeInstanceId::new("runtime-1").unwrap(),
        McpConnectionId::new("connection-1").unwrap(),
        McpSessionId::new("session-1").unwrap(),
        generation,
        discovery_digest,
    )
    .unwrap()
}

fn published() -> PublishedMcpTools {
    publish_mcp_tools(
        McpServerId::new("fixture-server").unwrap(),
        McpServerKind::Remote,
        vec![
            McpToolDescriptor::new("allowed", "1.0.0", json!({"type": "object"})).unwrap(),
            McpToolDescriptor::new("excluded", "1.0.0", json!({"type": "object"})).unwrap(),
        ],
        &["allowed"],
    )
    .unwrap()
}

#[test]
fn discovery_allowlist_publishes_only_selected_exact_tools() {
    let published = published();
    assert_eq!(published.snapshot().tool_refs().len(), 1);
    let tool_ref = &published.snapshot().tool_refs()[0];
    assert_eq!(tool_ref.tool_id().as_str(), "mcp::fixture-server::allowed");
    assert_eq!(
        published.resolve(tool_ref).unwrap().class(),
        ToolClass::McpRemote
    );
    assert!(
        published
            .snapshot()
            .tool_refs()
            .iter()
            .all(|reference| reference.tool_id().as_str() != "mcp::fixture-server::excluded")
    );
}

#[test]
fn denied_stale_replay_and_post_send_uncertainty_are_mediated_by_gateway() {
    let published = published();
    let discovery_digest = *published.discovery_digest();
    let tool_ref = published.snapshot().tool_refs()[0].clone();
    let calls = Arc::new(Mutex::new(Vec::new()));
    let sends = Arc::new(Mutex::new(0));
    let messages = Arc::new(Mutex::new(Vec::new()));
    let active = binding(1, discovery_digest);
    let generation = Arc::new(McpGenerationAuthority::new(&active));
    let denied = McpToolGateway::new(
        Admission {
            calls: Arc::clone(&calls),
            reject: Some(GateStage::Budget),
        },
        Client {
            sends: Arc::clone(&sends),
            messages: Arc::clone(&messages),
            fail_after_send: false,
            generation_cutover: None,
        },
        Arc::clone(&generation),
        ToolOutputBounds::new(1024, 16, 16).unwrap(),
    );
    let denied_capability = published
        .issue_dispatch(
            &active,
            &tool_ref,
            McpInvocationId::new("denied").unwrap(),
            json!({}),
        )
        .unwrap();
    assert!(denied.dispatch(denied_capability).is_err());
    assert_eq!(*sends.lock().unwrap(), 0);
    assert_eq!(
        *calls.lock().unwrap(),
        [
            GateStage::Capability,
            GateStage::Approval,
            GateStage::Budget
        ]
    );
    let wrong_connection = McpDispatchBinding::new(
        McpServerId::new("fixture-server").unwrap(),
        McpRuntimeInstanceId::new("runtime-1").unwrap(),
        McpConnectionId::new("connection-other").unwrap(),
        McpSessionId::new("session-1").unwrap(),
        1,
        discovery_digest,
    )
    .unwrap();
    let wrong_connection_capability = published
        .issue_dispatch(
            &wrong_connection,
            &tool_ref,
            McpInvocationId::new("wrong-connection").unwrap(),
            json!({}),
        )
        .unwrap();
    assert_eq!(
        denied.dispatch(wrong_connection_capability),
        Err(McpToolGatewayError::StaleGeneration)
    );
    assert_eq!(*sends.lock().unwrap(), 0);

    let stale_sends = Arc::new(Mutex::new(0));
    let stale_messages = Arc::new(Mutex::new(Vec::new()));
    let stale = McpToolGateway::new(
        Admission {
            calls: Arc::new(Mutex::new(Vec::new())),
            reject: None,
        },
        Client {
            sends: Arc::clone(&stale_sends),
            messages: stale_messages,
            fail_after_send: false,
            generation_cutover: None,
        },
        Arc::new(McpGenerationAuthority::new(&binding(2, discovery_digest))),
        ToolOutputBounds::new(1024, 16, 16).unwrap(),
    );
    let stale_capability = published
        .issue_dispatch(
            &active,
            &tool_ref,
            McpInvocationId::new("stale").unwrap(),
            json!({}),
        )
        .unwrap();
    assert_eq!(
        stale.dispatch(stale_capability),
        Err(McpToolGatewayError::StaleGeneration)
    );
    assert_eq!(*stale_sends.lock().unwrap(), 0);

    let uncertain_sends = Arc::new(Mutex::new(0));
    let uncertain_calls = Arc::new(Mutex::new(Vec::new()));
    let uncertain_messages = Arc::new(Mutex::new(Vec::new()));
    let guarded_generation = Arc::new(McpGenerationAuthority::new(&active));
    let next_binding = binding(2, discovery_digest);
    let uncertain = McpToolGateway::new(
        Admission {
            calls: Arc::clone(&uncertain_calls),
            reject: None,
        },
        Client {
            sends: Arc::clone(&uncertain_sends),
            messages: Arc::clone(&uncertain_messages),
            fail_after_send: true,
            generation_cutover: Some((Arc::clone(&guarded_generation), next_binding.clone())),
        },
        Arc::clone(&guarded_generation),
        ToolOutputBounds::new(1024, 16, 16).unwrap(),
    );
    let uncertain_capability = published
        .issue_dispatch(
            &active,
            &tool_ref,
            McpInvocationId::new("uncertain").unwrap(),
            json!({"x": 1}),
        )
        .unwrap();
    assert_eq!(
        uncertain.dispatch(uncertain_capability),
        Err(McpToolGatewayError::Gateway(
            ToolGatewayError::UncertainAfterAdmission
        ))
    );
    let replay_capability = published
        .issue_dispatch(
            &active,
            &tool_ref,
            McpInvocationId::new("uncertain").unwrap(),
            json!({"x": 1}),
        )
        .unwrap();
    assert_eq!(
        uncertain.dispatch(replay_capability),
        Err(McpToolGatewayError::Gateway(
            ToolGatewayError::UncertainAfterAdmission
        ))
    );
    assert_eq!(
        uncertain_messages.lock().unwrap()[0].params().unwrap()["name"],
        "allowed"
    );
    assert_eq!(*uncertain_sends.lock().unwrap(), 1);
    assert_eq!(
        *uncertain_calls.lock().unwrap(),
        [
            GateStage::Capability,
            GateStage::Approval,
            GateStage::Budget,
            GateStage::Containment,
            GateStage::EffectAdmission,
        ]
    );
    assert_eq!(
        uncertain.dispatch(
            published
                .issue_dispatch(
                    &active,
                    &tool_ref,
                    McpInvocationId::new("uncertain").unwrap(),
                    json!({"x": 2}),
                )
                .unwrap(),
        ),
        Err(McpToolGatewayError::Gateway(
            ToolGatewayError::DigestConflict
        ))
    );
    assert_eq!(*uncertain_sends.lock().unwrap(), 1);
    assert_eq!(guarded_generation.try_advance(&next_binding), Ok(()));
}

#[test]
fn excluded_or_wrong_snapshot_tools_cannot_mint_dispatch_authority() {
    let published = published();
    let active = binding(1, *published.discovery_digest());
    let excluded = ToolRef::new(
        ToolId::new("mcp::fixture-server::excluded").unwrap(),
        gocode_tools::ToolVersion::new("1.0.0").unwrap(),
    );
    assert!(
        published
            .issue_dispatch(
                &active,
                &excluded,
                McpInvocationId::new("excluded").unwrap(),
                json!({}),
            )
            .is_err()
    );
    assert!(
        published
            .issue_dispatch(
                &binding(1, [9; 32]),
                &published.snapshot().tool_refs()[0],
                McpInvocationId::new("wrong-snapshot").unwrap(),
                json!({}),
            )
            .is_err()
    );
}
