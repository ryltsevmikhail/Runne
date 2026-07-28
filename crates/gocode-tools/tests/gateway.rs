use std::sync::{Arc, Mutex};

use gocode_tools::{
    BlobRef, EffectAdmission, GateStage, RawToolOutput, ToolAdmissionDecision, ToolAdmissionError,
    ToolAdmissionPort, ToolCancelDisposition, ToolCancelRequest, ToolCloseEvidence,
    ToolCloseRequest, ToolDispatchRequest, ToolExecutionHandle, ToolExecutorError,
    ToolExecutorPort, ToolGateway, ToolGatewayError, ToolOutputBounds, ToolTerminalDisposition,
};

#[derive(Clone)]
struct RecordingAdmission {
    calls: Arc<Mutex<Vec<GateStage>>>,
    reject: Option<GateStage>,
}

impl ToolAdmissionPort for RecordingAdmission {
    fn check(
        &self,
        stage: GateStage,
        _request: &ToolDispatchRequest,
    ) -> Result<ToolAdmissionDecision, ToolAdmissionError> {
        self.calls.lock().unwrap().push(stage);
        if self.reject == Some(stage) {
            return Err(ToolAdmissionError::Rejected(stage));
        }
        Ok(if stage == GateStage::EffectAdmission {
            ToolAdmissionDecision::Winner(EffectAdmission {
                permit_id: "permit-1".into(),
            })
        } else {
            ToolAdmissionDecision::Passed
        })
    }
}

#[derive(Clone)]
struct RecordingExecutor {
    starts: Arc<Mutex<usize>>,
    cancels: Arc<Mutex<usize>>,
    fail_start: bool,
}

impl ToolExecutorPort for RecordingExecutor {
    fn start(
        &self,
        _request: &ToolDispatchRequest,
        admission: &EffectAdmission,
    ) -> Result<ToolExecutionHandle, ToolExecutorError> {
        *self.starts.lock().unwrap() += 1;
        if self.fail_start {
            return Err(ToolExecutorError::Unavailable);
        }
        assert_eq!(admission.permit_id, "permit-1");
        Ok(ToolExecutionHandle {
            execution_id: "execution-1".into(),
        })
    }

    fn signal_cancel(&self, _handle: &ToolExecutionHandle) -> Result<(), ToolExecutorError> {
        *self.cancels.lock().unwrap() += 1;
        Ok(())
    }
}

fn request(digest: u8) -> ToolDispatchRequest {
    ToolDispatchRequest {
        invocation_id: "invocation-1".into(),
        request_digest: [digest; 32],
    }
}

type TestGateway = (
    ToolGateway<RecordingAdmission, RecordingExecutor>,
    Arc<Mutex<Vec<GateStage>>>,
    Arc<Mutex<usize>>,
);

fn make_gateway(reject: Option<GateStage>) -> TestGateway {
    let calls = Arc::new(Mutex::new(Vec::new()));
    let starts = Arc::new(Mutex::new(0));
    let admission = RecordingAdmission {
        calls: Arc::clone(&calls),
        reject,
    };
    let executor = RecordingExecutor {
        starts: Arc::clone(&starts),
        cancels: Arc::new(Mutex::new(0)),
        fail_start: false,
    };
    (
        ToolGateway::new(admission, executor, ToolOutputBounds::new(8, 1, 1).unwrap()),
        calls,
        starts,
    )
}

#[test]
fn executor_failure_after_permit_is_uncertain_and_never_redispatched() {
    let calls = Arc::new(Mutex::new(Vec::new()));
    let starts = Arc::new(Mutex::new(0));
    let gateway = ToolGateway::new(
        RecordingAdmission {
            calls,
            reject: None,
        },
        RecordingExecutor {
            starts: Arc::clone(&starts),
            cancels: Arc::new(Mutex::new(0)),
            fail_start: true,
        },
        ToolOutputBounds::new(8, 1, 1).unwrap(),
    );

    assert_eq!(
        gateway.dispatch(request(1)),
        Err(ToolGatewayError::UncertainAfterAdmission)
    );
    assert_eq!(
        gateway.dispatch(request(1)),
        Err(ToolGatewayError::UncertainAfterAdmission)
    );
    assert_eq!(*starts.lock().unwrap(), 1);
}

#[test]
fn gates_run_in_fixed_order_before_executor() {
    let (gateway, calls, starts) = make_gateway(None);
    gateway.dispatch(request(1)).unwrap();

    assert_eq!(
        *calls.lock().unwrap(),
        [
            GateStage::Capability,
            GateStage::Approval,
            GateStage::Budget,
            GateStage::Containment,
            GateStage::EffectAdmission,
        ]
    );
    assert_eq!(*starts.lock().unwrap(), 1);
}

#[test]
fn rejection_leaves_later_gates_and_executor_untouched() {
    let (gateway, calls, starts) = make_gateway(Some(GateStage::Budget));
    assert_eq!(
        gateway.dispatch(request(1)),
        Err(ToolGatewayError::Admission(ToolAdmissionError::Rejected(
            GateStage::Budget
        )))
    );
    assert_eq!(
        *calls.lock().unwrap(),
        [
            GateStage::Capability,
            GateStage::Approval,
            GateStage::Budget
        ]
    );
    assert_eq!(*starts.lock().unwrap(), 0);
}

#[test]
fn exact_dispatch_replay_returns_handle_and_changed_digest_conflicts() {
    let (gateway, _calls, starts) = make_gateway(None);
    let first = gateway.dispatch(request(1)).unwrap();
    let replay = gateway.dispatch(request(1)).unwrap();
    assert_eq!(first, replay);
    assert_eq!(*starts.lock().unwrap(), 1);
    assert_eq!(
        gateway.dispatch(request(2)),
        Err(ToolGatewayError::DigestConflict)
    );
}

#[test]
fn restart_replay_uses_durable_existing_handle_without_redispatch() {
    #[derive(Clone)]
    struct DurableAdmission {
        claimed: Arc<Mutex<bool>>,
    }
    impl ToolAdmissionPort for DurableAdmission {
        fn check(
            &self,
            stage: GateStage,
            _request: &ToolDispatchRequest,
        ) -> Result<ToolAdmissionDecision, ToolAdmissionError> {
            if stage != GateStage::EffectAdmission {
                return Ok(ToolAdmissionDecision::Passed);
            }
            let mut claimed = self.claimed.lock().unwrap();
            if *claimed {
                Ok(ToolAdmissionDecision::Existing(ToolExecutionHandle {
                    execution_id: "execution-1".into(),
                }))
            } else {
                *claimed = true;
                Ok(ToolAdmissionDecision::Winner(EffectAdmission {
                    permit_id: "permit-1".into(),
                }))
            }
        }
    }

    let claimed = Arc::new(Mutex::new(false));
    let starts = Arc::new(Mutex::new(0));
    let executor = || RecordingExecutor {
        starts: Arc::clone(&starts),
        cancels: Arc::new(Mutex::new(0)),
        fail_start: false,
    };
    let first = ToolGateway::new(
        DurableAdmission {
            claimed: Arc::clone(&claimed),
        },
        executor(),
        ToolOutputBounds::new(8, 1, 1).unwrap(),
    );
    assert_eq!(
        first.dispatch(request(1)).unwrap().execution_id,
        "execution-1"
    );

    let restarted = ToolGateway::new(
        DurableAdmission { claimed },
        executor(),
        ToolOutputBounds::new(8, 1, 1).unwrap(),
    );
    assert_eq!(
        restarted.dispatch(request(1)).unwrap().execution_id,
        "execution-1"
    );
    assert_eq!(*starts.lock().unwrap(), 1);
}

#[test]
fn bounded_output_is_explicitly_truncated_with_blob_reference() {
    let (gateway, _, _) = make_gateway(None);
    let handle = gateway.dispatch(request(1)).unwrap();
    let result = gateway
        .close(ToolCloseRequest {
            invocation_id: "invocation-1".into(),
            request_digest: [1; 32],
            handle,
            evidence: ToolCloseEvidence {
                process_terminal: true,
                containment_released: true,
                cleanup_closed: true,
            },
            output: RawToolOutput {
                bytes: b"123456789".to_vec(),
                lines: vec!["first".into(), "second".into()],
                items: vec![serde_json::json!(1), serde_json::json!(2)],
                overflow_blob: Some(BlobRef::new("sha256:overflow").unwrap()),
            },
        })
        .unwrap();

    let ToolTerminalDisposition::Completed(output) = result else {
        panic!("expected completed output");
    };
    assert!(output.truncated());
    assert_eq!(output.bytes(), b"12345678");
    assert!(output.lines().is_empty());
    assert!(output.items().is_empty());
    assert_eq!(output.overflow_blob().unwrap().as_str(), "sha256:overflow");
}

#[test]
fn byte_bound_covers_structured_lines_and_items() {
    let (gateway, _, _) = make_gateway(None);
    let handle = gateway.dispatch(request(1)).unwrap();
    let result = gateway
        .close(ToolCloseRequest {
            invocation_id: "invocation-1".into(),
            request_digest: [1; 32],
            handle,
            evidence: ToolCloseEvidence {
                process_terminal: true,
                containment_released: true,
                cleanup_closed: true,
            },
            output: RawToolOutput {
                lines: vec!["a".repeat(64)],
                items: vec![serde_json::json!({"large": "b".repeat(64)})],
                overflow_blob: Some(BlobRef::new("sha256:structured-overflow").unwrap()),
                ..RawToolOutput::default()
            },
        })
        .unwrap();

    let ToolTerminalDisposition::Completed(output) = result else {
        panic!("expected completed output");
    };
    assert!(output.truncated());
    assert!(output.lines().is_empty());
    assert!(output.items().is_empty());
}

#[test]
fn missing_overflow_or_cleanup_evidence_is_uncertain() {
    let (gateway, _, _) = make_gateway(None);
    let handle = gateway.dispatch(request(1)).unwrap();
    let result = gateway
        .close(ToolCloseRequest {
            invocation_id: "invocation-1".into(),
            request_digest: [1; 32],
            handle,
            evidence: ToolCloseEvidence {
                process_terminal: true,
                containment_released: true,
                cleanup_closed: false,
            },
            output: RawToolOutput::default(),
        })
        .unwrap();
    assert_eq!(result, ToolTerminalDisposition::Uncertain);

    let (gateway, _, _) = make_gateway(None);
    let handle = gateway.dispatch(request(1)).unwrap();
    assert_eq!(
        gateway.close(ToolCloseRequest {
            invocation_id: "invocation-1".into(),
            request_digest: [1; 32],
            handle,
            evidence: ToolCloseEvidence {
                process_terminal: true,
                containment_released: true,
                cleanup_closed: true,
            },
            output: RawToolOutput {
                bytes: vec![0; 9],
                ..RawToolOutput::default()
            },
        }),
        Ok(ToolTerminalDisposition::Uncertain)
    );
}

#[test]
fn cancel_is_idempotent_and_does_not_close_execution() {
    let (gateway, _, _) = make_gateway(None);
    let handle = gateway.dispatch(request(1)).unwrap();
    let cancel = ToolCancelRequest {
        invocation_id: "invocation-1".into(),
        request_digest: [1; 32],
        handle,
    };
    assert_eq!(
        gateway.signal_cancel(cancel.clone()).unwrap(),
        ToolCancelDisposition::Signalled
    );
    assert_eq!(
        gateway.signal_cancel(cancel).unwrap(),
        ToolCancelDisposition::AlreadySignalled
    );
}
