use std::{collections::BTreeMap, sync::{Arc, Mutex}};
use runne_mcp::*;
use runne_tools::*;
use serde_json::json;

#[derive(Clone)] struct Admission { calls: Arc<Mutex<Vec<GateStage>>>, reject: Option<GateStage> }
impl ToolAdmissionPort for Admission {
    fn check(&self, stage: GateStage, _: &ToolDispatchRequest) -> Result<ToolAdmissionDecision, ToolAdmissionError> {
        self.calls.lock().unwrap().push(stage);
        if self.reject == Some(stage) { return Err(ToolAdmissionError::Rejected(stage)); }
        Ok(if stage == GateStage::EffectAdmission { ToolAdmissionDecision::Winner(EffectAdmission { permit_id: "mcp-permit".into() }) } else { ToolAdmissionDecision::Passed })
    }
}
struct Reservation { digest: [u8; 32], permit: String, handle: ToolExecutionHandle, terminal: bool, settled: bool }
struct Client { sends: Arc<Mutex<usize>>, messages: Arc<Mutex<Vec<McpNormalizedMessage>>>, fail_after_send: bool, generation_cutover: Option<(Arc<McpGenerationAuthority>, McpDispatchBinding)>, reservations: Arc<Mutex<BTreeMap<String, Reservation>>> }
impl McpClientPort for Client {
    fn dispatch(&mut self, message: &McpNormalizedMessage) -> Result<(), McpTransportError> {
        *self.sends.lock().unwrap() += 1; self.messages.lock().unwrap().push(message.clone());
        if let Some(McpRequestId::String(id)) = message.request_id() { self.reservations.lock().unwrap().get_mut(id).ok_or(McpTransportError::Unavailable)?.terminal = true; }
        if let Some((a, b)) = &self.generation_cutover { assert_eq!(a.try_advance(b), Err(McpGenerationAdvanceError::Busy)); }
        if self.fail_after_send { Err(McpTransportError::Unavailable) } else { Ok(()) }
    }
    fn receive(&mut self) -> Result<McpNormalizedMessage, McpTransportError> { Err(McpTransportError::Unavailable) }
}
impl McpProtocolCompletionPort for Client {
    fn reserve_protocol_completion(&mut self, r: &ToolDispatchRequest, a: &EffectAdmission, h: &ToolExecutionHandle) -> Result<(), McpTransportError> {
        if a.permit_id.is_empty() { return Err(McpTransportError::Unavailable); }
        let next = Reservation { digest: r.request_digest, permit: a.permit_id.clone(), handle: h.clone(), terminal: false, settled: false };
        let mut entries = self.reservations.lock().unwrap();
        match entries.get(&r.invocation_id) { Some(old) if old.digest != next.digest || old.permit != next.permit || old.handle != next.handle => Err(McpTransportError::Unavailable), Some(_) => Ok(()), None => { entries.insert(r.invocation_id.clone(), next); Ok(()) } }
    }
    fn confirm_protocol_completion(&mut self, r: &ToolProtocolCloseRequest) -> Result<(), McpTransportError> {
        let mut entries = self.reservations.lock().unwrap();
        let entry = entries.get_mut(&r.invocation_id).ok_or(McpTransportError::Unavailable)?;
        if entry.digest != r.request_digest || entry.handle != r.handle || !entry.terminal || entry.settled { return Err(McpTransportError::Unavailable); }
        entry.settled = true; Ok(())
    }
}
fn binding(g: u64, d: [u8; 32]) -> McpDispatchBinding { McpDispatchBinding::new(McpServerId::new("fixture-server").unwrap(), McpRuntimeInstanceId::new("runtime-1").unwrap(), McpConnectionId::new("connection-1").unwrap(), McpSessionId::new("session-1").unwrap(), g, d).unwrap() }
fn published() -> PublishedMcpTools { publish_mcp_tools(McpServerId::new("fixture-server").unwrap(), McpServerKind::Remote, vec![McpToolDescriptor::new("allowed", "1.0.0", json!({"type":"object"})).unwrap(), McpToolDescriptor::new("excluded", "1.0.0", json!({"type":"object"})).unwrap()], &["allowed"]).unwrap() }
fn reservations() -> Arc<Mutex<BTreeMap<String, Reservation>>> { Arc::new(Mutex::new(BTreeMap::new())) }
