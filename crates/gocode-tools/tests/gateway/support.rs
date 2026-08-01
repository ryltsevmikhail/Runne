use std::sync::{Arc, Mutex};

use gocode_tools::{
    BlobRef, EffectAdmission, GateStage, RawToolOutput, ToolAdmissionDecision, ToolAdmissionError,
    ToolAdmissionPort, ToolCancelDisposition, ToolCancelRequest, ToolCloseEvidence,
    ToolCloseRequest, ToolDispatchBinding, ToolDispatchRequest, ToolExecutionHandle,
    ToolExecutorError, ToolExecutorPort, ToolGateway, ToolGatewayError, ToolId, ToolOutputBounds,
    ToolRef, ToolTerminalDisposition, ToolVersion,
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
        binding: ToolDispatchBinding::new(
            ToolRef::new(
                ToolId::new("fixture::tool").unwrap(),
                ToolVersion::new("1.0.0").unwrap(),
            ),
            "fixture-activation".into(),
            [1; 32],
            1,
            [2; 32],
        ),
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
