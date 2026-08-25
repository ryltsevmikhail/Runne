use std::str::FromStr;

use runne_api::{
    ApiActor, ApiPrincipalId, ExistingProcessCommand, ProcessCommandContext, ProcessHostPort,
    ProcessOutputPage, ProcessQueryContext, ProcessSnapshot, ProcessState, StartProcessCommand,
};
use runne_application::ports::ProcessProvider;
use runne_domain::id::{
    AttemptId, CommandId, IdempotencyKey, InvocationId, ProcessId, TaskRunId, WorkspaceId,
};
use runne_runtime::RuntimeProcessHost;

#[derive(Clone, Copy)]
struct FakeProvider;

impl ProcessProvider for FakeProvider {
    fn start_process(
        &self,
        _context: &ProcessCommandContext,
        command: &StartProcessCommand,
    ) -> Result<ProcessSnapshot, runne_api::ProcessHostError> {
        let _ = command;
        Ok(snapshot(id("018f2e3a-7000-7000-8000-000000000011")))
    }
    fn get_process(
        &self,
        _context: &ProcessQueryContext,
        process_id: ProcessId,
    ) -> Result<ProcessSnapshot, runne_api::ProcessHostError> {
        Ok(snapshot(process_id))
    }
    fn read_process_output(
        &self,
        _context: &ProcessQueryContext,
        _process_id: ProcessId,
        _after_sequence: u64,
        limit: u16,
    ) -> Result<ProcessOutputPage, runne_api::ProcessHostError> {
        ProcessOutputPage::new(limit, Vec::new())
    }
    fn stop_process(
        &self,
        _context: &ProcessCommandContext,
        command: &ExistingProcessCommand,
    ) -> Result<ProcessSnapshot, runne_api::ProcessHostError> {
        Ok(snapshot(command.process_id))
    }
}

fn id<T: FromStr>(value: &str) -> T
where
    T::Err: std::fmt::Debug,
{
    value.parse().expect("uuidv7")
}

fn snapshot(process_id: ProcessId) -> ProcessSnapshot {
    ProcessSnapshot {
        process_id,
        invocation_id: id("018f2e3a-7000-7000-8000-000000000009"),
        workspace_id: id("018f2e3a-7000-7000-8000-000000000001"),
        state: ProcessState::Running,
        version: 1,
        next_output_sequence: 1,
    }
}

fn context() -> ProcessCommandContext {
    ProcessCommandContext {
        command_id: id::<CommandId>("018f2e3a-7000-7000-8000-000000000010"),
        idempotency_key: IdempotencyKey::new("process-1").unwrap(),
        principal: ApiPrincipalId::new("local-owner").unwrap(),
        actor: ApiActor::new("desktop").unwrap(),
    }
}

#[tokio::test]
async fn runtime_process_host_delegates_typed_lifecycle_and_output() {
    let host = RuntimeProcessHost::new(FakeProvider);
    let start = StartProcessCommand {
        workspace_id: id::<WorkspaceId>("018f2e3a-7000-7000-8000-000000000001"),
        task_run_id: id::<TaskRunId>("018f2e3a-7000-7000-8000-000000000002"),
        attempt_id: id::<AttemptId>("018f2e3a-7000-7000-8000-000000000003"),
        invocation_id: id::<InvocationId>("018f2e3a-7000-7000-8000-000000000009"),
    };
    let snapshot = host.start_process(context(), start).await.unwrap();
    assert_eq!(snapshot.state, ProcessState::Running);
    let query = ProcessQueryContext {
        principal: ApiPrincipalId::new("local-owner").unwrap(),
    };
    assert_eq!(
        host.get_process(query.clone(), snapshot.process_id)
            .await
            .unwrap(),
        snapshot
    );
    assert_eq!(
        host.read_process_output(query, snapshot.process_id, 0, 4)
            .await
            .unwrap()
            .chunks(),
        &[]
    );
    assert_eq!(
        host.stop_process(
            context(),
            ExistingProcessCommand {
                process_id: snapshot.process_id,
                expected_version: snapshot.version,
            },
        )
        .await
        .unwrap(),
        snapshot
    );
    host.shutdown().await;
}
