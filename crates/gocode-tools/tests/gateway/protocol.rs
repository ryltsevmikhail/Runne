#[test]
fn protocol_closure_requires_executor_owned_confirmation_and_replays_exactly() {
    let (gateway, state) = make_protocol_gateway();
    let request = request(8);
    let handle = gateway.dispatch(request.clone()).unwrap();
    let close = || ToolProtocolCloseRequest::new("invocation-1".into(), [8; 32], handle.clone());
    assert_eq!(gateway.close_protocol(close()), Err(ToolGatewayError::ProtocolClosureConflict));
    assert_eq!(
        gateway.close_protocol(ToolProtocolCloseRequest::new("invocation-1".into(), [9; 32], handle.clone())),
        Err(ToolGatewayError::DigestConflict)
    );
    assert_eq!(gateway.close_protocol(ToolProtocolCloseRequest::new("invocation-1".into(), [8; 32], ToolExecutionHandle { execution_id: "wrong".into() })), Err(ToolGatewayError::ExecutionNotFound));
    state.lock().unwrap().terminal_claimed = true;
    let completed = gateway.close_protocol(close()).unwrap();
    assert!(matches!(completed, ToolTerminalDisposition::Completed(_)));
    assert_eq!(gateway.close_protocol(close()).unwrap(), completed);
    let state = state.lock().unwrap();
    assert_eq!(state.attempts, 2);
    assert_eq!(state.settlements, 1);
}

#[test]
fn rejected_protocol_dispatch_does_not_reach_executor() {
    let state = Arc::new(Mutex::new(ProtocolProofState::default()));
    let gateway = ToolGateway::new(
        RecordingAdmission { calls: Arc::new(Mutex::new(Vec::new())), reject: Some(GateStage::Budget) },
        RecordingProtocolExecutor { state: Arc::clone(&state) },
        ToolOutputBounds::new(8, 1, 1).unwrap(),
    );
    assert_eq!(gateway.dispatch(request(8)), Err(ToolGatewayError::Admission(ToolAdmissionError::Rejected(GateStage::Budget))));
    assert!(state.lock().unwrap().expected.is_none());
}
