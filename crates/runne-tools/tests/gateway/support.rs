use std::sync::{Arc, Mutex};
use runne_tools::*;

#[derive(Clone)] struct RecordingAdmission { calls: Arc<Mutex<Vec<GateStage>>>, reject: Option<GateStage> }
impl ToolAdmissionPort for RecordingAdmission {
    fn check(&self, stage: GateStage, _: &ToolDispatchRequest) -> Result<ToolAdmissionDecision, ToolAdmissionError> {
        self.calls.lock().unwrap().push(stage);
        if self.reject == Some(stage) { return Err(ToolAdmissionError::Rejected(stage)); }
        Ok(if stage == GateStage::EffectAdmission { ToolAdmissionDecision::Winner(EffectAdmission { permit_id: "permit-1".into() }) } else { ToolAdmissionDecision::Passed })
    }
}

#[derive(Clone)] struct RecordingExecutor { starts: Arc<Mutex<usize>>, cancels: Arc<Mutex<usize>>, fail_start: bool }
impl ToolExecutorPort for RecordingExecutor {
    type CompletionMode = ProcessCompletion;
    fn start(&self, _: &ToolDispatchRequest, admission: &EffectAdmission) -> Result<ToolExecutionHandle, ToolExecutorError> {
        *self.starts.lock().unwrap() += 1;
        if self.fail_start { return Err(ToolExecutorError::Unavailable); }
        assert_eq!(admission.permit_id, "permit-1");
        Ok(ToolExecutionHandle { execution_id: "execution-1".into() })
    }
    fn signal_cancel(&self, _: &ToolExecutionHandle) -> Result<(), ToolExecutorError> { *self.cancels.lock().unwrap() += 1; Ok(()) }
}
impl ProcessToolExecutorPort for RecordingExecutor {}

#[derive(Default)] struct ProtocolProofState { expected: Option<ToolProtocolCloseRequest>, terminal_claimed: bool, attempts: usize, settlements: usize }
#[derive(Clone)] struct RecordingProtocolExecutor { state: Arc<Mutex<ProtocolProofState>> }
impl ToolExecutorPort for RecordingProtocolExecutor {
    type CompletionMode = ProtocolCompletion;
    fn start(&self, request: &ToolDispatchRequest, admission: &EffectAdmission) -> Result<ToolExecutionHandle, ToolExecutorError> { assert_eq!(admission.permit_id, "permit-1"); let handle = ToolExecutionHandle { execution_id: "execution-1".into() }; let mut state = self.state.lock().unwrap(); state.expected = Some(ToolProtocolCloseRequest::new(request.invocation_id.clone(), request.request_digest, handle.clone())); Ok(handle) }
    fn signal_cancel(&self, _: &ToolExecutionHandle) -> Result<(), ToolExecutorError> { Ok(()) }
}
impl ProtocolToolExecutorPort for RecordingProtocolExecutor {
    fn confirm_protocol_completion(&self, request: &ToolProtocolCloseRequest) -> Result<(), ToolExecutorError> { let mut state = self.state.lock().unwrap(); state.attempts += 1; if !state.terminal_claimed || state.expected.as_ref() != Some(request) || state.settlements != 0 { return Err(ToolExecutorError::Rejected); } state.settlements += 1; Ok(()) }
}

fn request(digest: u8) -> ToolDispatchRequest { ToolDispatchRequest { invocation_id: "invocation-1".into(), request_digest: [digest; 32], binding: ToolDispatchBinding::new(ToolRef::new(ToolId::new("fixture::tool").unwrap(), ToolVersion::new("1.0.0").unwrap()), "fixture-activation".into(), [1; 32], 1, [2; 32]) } }
type TestGateway = (ToolGateway<RecordingAdmission, RecordingExecutor>, Arc<Mutex<Vec<GateStage>>>, Arc<Mutex<usize>>);
fn make_gateway(reject: Option<GateStage>) -> TestGateway {
    let calls = Arc::new(Mutex::new(Vec::new())); let starts = Arc::new(Mutex::new(0));
    let admission = RecordingAdmission { calls: Arc::clone(&calls), reject };
    let executor = RecordingExecutor { starts: Arc::clone(&starts), cancels: Arc::new(Mutex::new(0)), fail_start: false };
    (ToolGateway::new(admission, executor, ToolOutputBounds::new(8, 1, 1).unwrap()), calls, starts)
}

fn make_protocol_gateway() -> (ToolGateway<RecordingAdmission, RecordingProtocolExecutor>, Arc<Mutex<ProtocolProofState>>) { let state = Arc::new(Mutex::new(ProtocolProofState::default())); let admission = RecordingAdmission { calls: Arc::new(Mutex::new(Vec::new())), reject: None }; let executor = RecordingProtocolExecutor { state: Arc::clone(&state) }; (ToolGateway::new(admission, executor, ToolOutputBounds::new(8, 1, 1).unwrap()), state) }
