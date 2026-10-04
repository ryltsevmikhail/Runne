use std::sync::{Arc, Mutex};

use axum::body::{Body, to_bytes};
use http::{Request, Response, StatusCode};
use runne_api::{
    ApiActor, CanonicalTaskRunState, CanonicalTerminalResult, CompleteTaskRunCommand,
    CreateTaskRunCommand, ExistingTaskRunCommand, LegacySubmitTaskRunCommand, RemoteAccountingV1,
    RemoteCancellationV1, RemoteEffectAvailabilityV1, RemoteEffectCapabilitiesV1,
    RemoteEffectOutcomeV1, RemoteEffectV1, RemotePublicationV1, SubmitTaskRunCommand,
    SuccessorEligibilityV1, TaskRunCommandAck, TaskRunCommandAckKind, TaskRunCommandContext,
    TaskRunCommandHostPort, TaskRunEffectsV1, TaskRunHostError, TaskRunQueryHostPort,
    TaskRunSnapshot,
};
use runne_domain::id::{AttemptId, TaskRunId};
use runne_http::admission::AdmissionState;
use runne_http::health::{HealthState, RecoveryState};
use runne_http::router::create_router_with_task_run_profile;
use runne_http::task_runs::TaskRunHttpState;
use runne_security::SecretBroker;
use serde_json::Value;
use tower::ServiceExt;

const TOKEN: [u8; 32] = [0xAB; 32];
const TASKRUN_ID: &str = "018f2e3a-7000-7000-8000-000000000040";
const ATTEMPT_ID: &str = "018f2e3a-7000-7000-8000-000000000041";
const CONVERSATION_ID: &str = "018f2e3a-7000-7000-8000-000000000042";
const WORKSPACE_ID: &str = "018f2e3a-7000-7000-8000-000000000043";

#[derive(Debug, Clone, PartialEq, Eq)]
enum Call {
    Create(TaskRunCommandContext, CreateTaskRunCommand),
    Submit(TaskRunCommandContext, SubmitTaskRunCommand),
    LegacySubmit(TaskRunCommandContext, LegacySubmitTaskRunCommand),
    Queue(TaskRunCommandContext, ExistingTaskRunCommand),
    Admit(TaskRunCommandContext, ExistingTaskRunCommand),
    Cancel(TaskRunCommandContext, ExistingTaskRunCommand),
    Start(TaskRunCommandContext, ExistingTaskRunCommand),
    Complete(TaskRunCommandContext, CompleteTaskRunCommand),
    Get(TaskRunId),
}

#[derive(Clone, Default)]
struct RecordingHost {
    calls: Arc<Mutex<Vec<Call>>>,
    next_error: Arc<Mutex<Option<TaskRunHostError>>>,
}

impl RecordingHost {
    fn calls(&self) -> Vec<Call> {
        self.calls.lock().unwrap().clone()
    }

    fn fail_next(&self, error: TaskRunHostError) {
        *self.next_error.lock().unwrap() = Some(error);
    }

    fn record(&self, call: Call) -> Result<(), TaskRunHostError> {
        self.calls.lock().unwrap().push(call);
        match self.next_error.lock().unwrap().take() {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }
}

impl TaskRunCommandHostPort for RecordingHost {
    async fn create_task_run(
        &self,
        context: TaskRunCommandContext,
        command: CreateTaskRunCommand,
    ) -> Result<TaskRunCommandAck, TaskRunHostError> {
        self.record(Call::Create(context, command))?;
        Ok(TaskRunCommandAck {
            taskrun_id: TASKRUN_ID.parse().unwrap(),
            new_version: 1,
            kind: TaskRunCommandAckKind::Created,
        })
    }

    async fn submit_task_run(
        &self,
        context: TaskRunCommandContext,
        command: SubmitTaskRunCommand,
    ) -> Result<TaskRunCommandAck, TaskRunHostError> {
        self.record(Call::Submit(context, command))?;
        Ok(TaskRunCommandAck {
            taskrun_id: TASKRUN_ID.parse().unwrap(),
            new_version: 2,
            kind: TaskRunCommandAckKind::Submitted,
        })
    }

    async fn submit_task_run_legacy(
        &self,
        context: TaskRunCommandContext,
        command: LegacySubmitTaskRunCommand,
    ) -> Result<TaskRunCommandAck, TaskRunHostError> {
        self.record(Call::LegacySubmit(context, command))?;
        Ok(TaskRunCommandAck {
            taskrun_id: TASKRUN_ID.parse().unwrap(),
            new_version: 2,
            kind: TaskRunCommandAckKind::Submitted,
        })
    }

    async fn queue_task_run(
        &self,
        context: TaskRunCommandContext,
        command: ExistingTaskRunCommand,
    ) -> Result<TaskRunCommandAck, TaskRunHostError> {
        self.record(Call::Queue(context, command))?;
        Ok(TaskRunCommandAck {
            taskrun_id: command.taskrun_id,
            new_version: command.expected_version + 1,
            kind: TaskRunCommandAckKind::Queued,
        })
    }

    async fn admit_task_run(
        &self,
        context: TaskRunCommandContext,
        command: ExistingTaskRunCommand,
    ) -> Result<TaskRunCommandAck, TaskRunHostError> {
        self.record(Call::Admit(context, command))?;
        Ok(TaskRunCommandAck {
            taskrun_id: command.taskrun_id,
            new_version: command.expected_version + 1,
            kind: TaskRunCommandAckKind::Admitted,
        })
    }

    async fn request_task_run_cancellation(
        &self,
        context: TaskRunCommandContext,
        command: ExistingTaskRunCommand,
    ) -> Result<TaskRunCommandAck, TaskRunHostError> {
        self.record(Call::Cancel(context, command))?;
        Ok(TaskRunCommandAck {
            taskrun_id: command.taskrun_id,
            new_version: command.expected_version + 1,
            kind: TaskRunCommandAckKind::CancellationRequested,
        })
    }

    async fn start_attempt(
        &self,
        context: TaskRunCommandContext,
        command: ExistingTaskRunCommand,
    ) -> Result<TaskRunCommandAck, TaskRunHostError> {
        self.record(Call::Start(context, command))?;
        Ok(TaskRunCommandAck {
            taskrun_id: command.taskrun_id,
            new_version: command.expected_version + 1,
            kind: TaskRunCommandAckKind::AttemptStarted {
                attempt_id: ATTEMPT_ID.parse::<AttemptId>().unwrap(),
            },
        })
    }

    async fn complete_task_run(
        &self,
        context: TaskRunCommandContext,
        command: CompleteTaskRunCommand,
    ) -> Result<TaskRunCommandAck, TaskRunHostError> {
        self.record(Call::Complete(context, command.clone()))?;
        Ok(TaskRunCommandAck {
            taskrun_id: command.taskrun_id,
            new_version: command.expected_version + 1,
            kind: TaskRunCommandAckKind::Completed {
                result: command.result,
            },
        })
    }
}

impl TaskRunQueryHostPort for RecordingHost {
    async fn get_task_run(
        &self,
        taskrun_id: TaskRunId,
    ) -> Result<TaskRunSnapshot, TaskRunHostError> {
        self.record(Call::Get(taskrun_id))?;
        Ok(TaskRunSnapshot {
            taskrun_id,
            conversation_id: None,
            workspace_id: None,
            state: CanonicalTaskRunState::Running,
            stream_version: 4,
            active_attempt_id: Some(ATTEMPT_ID.parse().unwrap()),
            terminal_result: None,
        })
    }

    async fn get_task_run_effects(
        &self,
        taskrun_id: TaskRunId,
    ) -> Result<TaskRunEffectsV1, TaskRunHostError> {
        Ok(TaskRunEffectsV1 {
            taskrun_id,
            stream_version: 4,
            attempt_id: Some(ATTEMPT_ID.parse().unwrap()),
            cancellation_requested: false,
            local_command: None,
            remote: RemoteEffectV1 {
                outcome: RemoteEffectOutcomeV1::Unknown,
                publication: RemotePublicationV1::Unknown,
                accounting: RemoteAccountingV1::Unknown,
                cancellation: RemoteCancellationV1::NotRequested,
                availability: RemoteEffectAvailabilityV1::Unknown,
                capabilities: RemoteEffectCapabilitiesV1 {
                    status_check: false,
                    stream_resume: false,
                    remote_cancel: false,
                },
                usage_known: None,
            },
            successor: SuccessorEligibilityV1::RequiresDuplicateEffectAcknowledgment,
        })
    }
}

fn app(host: RecordingHost) -> axum::Router {
    create_router_with_task_run_profile(
        TOKEN,
        HealthState {
            recovery_state: RecoveryState::Ready,
        },
        AdmissionState::new(RecoveryState::Ready),
        TaskRunHttpState::new(host, ApiActor::new("runne-http-test").unwrap(), None)
            .with_prohibited_content(Arc::new(SecretBroker::new().prohibited_content_guard())),
        runne_http::runtime_profile::RuntimeProfileHttpState::new(
            "test",
            "test",
            "0.1.0-test",
            &["task_run.submit.v2"],
        ),
    )
}

fn command_request(uri: &str, sequence: u8, key: &str, body: impl Into<Body>) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri(uri)
        .header("content-type", "application/json")
        .header("authorization", format!("Bearer {}", hex::encode(TOKEN)))
        .header(
            "x-command-id",
            format!("018f2e3a-7000-7000-8000-0000000000{sequence:02x}"),
        )
        .header("idempotency-key", key)
        .body(body.into())
        .unwrap()
}

fn query_request(uri: &str) -> Request<Body> {
    Request::builder()
        .method("GET")
        .uri(uri)
        .header("authorization", format!("Bearer {}", hex::encode(TOKEN)))
        .body(Body::empty())
        .unwrap()
}

async fn json(response: Response<Body>) -> Value {
    let bytes = to_bytes(response.into_body(), 64 * 1024).await.unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

async fn assert_error(response: Response<Body>, status: StatusCode, code: &str) {
    assert_eq!(response.status(), status);
    let request_id = response
        .headers()
        .get("x-request-id")
        .unwrap()
        .to_str()
        .unwrap()
        .to_owned();
    let body = json(response).await;
    assert_eq!(body["code"], code);
    assert_eq!(body["requestId"], request_id);
}
