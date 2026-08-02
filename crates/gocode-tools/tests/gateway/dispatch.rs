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
    let mut changed_binding = request(1);
    changed_binding.binding = ToolDispatchBinding::new(
        ToolRef::new(
            ToolId::new("fixture::tool").unwrap(),
            ToolVersion::new("1.0.0").unwrap(),
        ),
        "fixture-activation".into(),
        [1; 32],
        2,
        [2; 32],
    );
    assert_eq!(
        gateway.dispatch(changed_binding),
        Err(ToolGatewayError::AuthorityBindingConflict)
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
