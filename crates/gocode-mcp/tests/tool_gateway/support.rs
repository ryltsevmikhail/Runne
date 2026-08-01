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
