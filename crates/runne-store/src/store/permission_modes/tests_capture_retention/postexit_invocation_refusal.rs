//! Genuine fresh request denied after unknown recovery; no second admission/GO.
use super::super::{
    fixture,
    target::binding::{self, BindingRequest},
};
use super::{
    invocation_control,
    invocation_owner::OwnerView,
    invocation_request::RequestRecord,
    invocation_rows::{self, Rows},
    metadata::Area,
    observations, paths,
};
use crate::{
    ProjectTrustStore,
    store::{LocalCommandAttemptState, StoreTransaction, taskrun_claim},
};
use runne_application::{
    ports::{EventStoreError, TaskRunClaimError},
    project_trust::{ProjectTrustPersistence, ProjectTrustProjectId},
};
use runne_domain::{
    id::{InvocationId, ProjectId},
    task_run::{TaskRunExecutable, TaskRunLocalCommand, TaskRunState},
};
use std::{path::Path, sync::Arc};

pub(super) fn assert_refused(
    root: &Path,
    saved: &Area,
    original: &StoreTransaction,
    trust: Arc<ProjectTrustStore>,
    settled_version: u64,
) {
    let request: RequestRecord = paths::read(root, "request.json");
    assert_eq!(&request.area, saved);
    let before = Rows::read(
        &observations::reader(root, saved),
        saved.identity().taskrun_id,
    );
    before.count("x2_permission_bindings", 1);
    before.count("x2_permission_spent", 1);
    before.count("x2_permission_human", 1);
    before.count("x2_permission_admission", 1);
    let stream = observations::stream(original, saved, TaskRunState::Unrecoverable);
    assert_eq!(stream.0, settled_version);
    observations::capture(original, saved, LocalCommandAttemptState::OutcomeUnknown);
    let owner = OwnerView::reopen(root, saved, trust.clone());
    assert_eq!(
        Rows::read(
            &observations::reader(root, saved),
            saved.identity().taskrun_id
        ),
        before
    );
    let command = TaskRunLocalCommand::new(
        TaskRunExecutable::workspace_relative("tool".into()).unwrap(),
        ".".into(),
        vec![
            "tool".into(),
            "-c".into(),
            "printf once >> effect-marker".into(),
        ],
        vec![],
    )
    .unwrap();
    assert_eq!(command.intent_digest(), saved.command_digest);
    let prepared = owner.prepare(command.clone());
    let observation = prepared.observation();
    assert_eq!(observation.workspace_identity(), observation.cwd_identity());
    let invocation = InvocationId::from_bytes(uuid::Uuid::now_v7().into_bytes());
    let binding = binding::build(
        &owner.context(),
        BindingRequest {
            command: command.clone(),
            assignment: saved.identity(),
            claim_stream_version: request.claim_stream_version,
            observation,
            invocation_id: invocation,
            expires_at_unix_ms: request.approval_expires_at_unix_ms,
        },
    );
    request.assert_original_and_fresh(saved, &binding, observation, fixture::now());
    let executable = std::fs::read(root.join(&saved.nested).join("workspace/tool")).unwrap();
    invocation_control::capture_and_settle(command, &executable);
    request.assert_original_and_fresh(saved, &binding, observation, fixture::now());
    {
        let c = observations::reader(root, saved);
        assert_eq!(Rows::read(&c, saved.identity().taskrun_id), before);
        invocation_rows::fresh_absent(&c, invocation);
        let task = taskrun_claim::verify_assignment_history(&c, &saved.identity()).unwrap();
        assert_eq!(task.state(), TaskRunState::Unrecoverable);
        assert!(matches!(
            taskrun_claim::verify_active_assignment(&c, &saved.identity()),
            Err(TaskRunClaimError::NotQueued)
        ));
    }
    let result = owner
        .store
        .capture_local_command_permission(&binding, observation);
    assert!(
        matches!(result, Err(EventStoreError::CorruptData)),
        "exact public refusal expected, got {result:?}"
    );
    {
        let c = observations::reader(root, saved);
        invocation_rows::fresh_absent(&c, invocation);
        assert_eq!(Rows::read(&c, saved.identity().taskrun_id), before);
    }
    observations::capture(
        &owner.store,
        saved,
        LocalCommandAttemptState::OutcomeUnknown,
    );
    assert_eq!(
        observations::stream(&owner.store, saved, TaskRunState::Unrecoverable),
        stream
    );
    assert_eq!(
        observations::stream(original, saved, TaskRunState::Unrecoverable),
        stream
    );
    let project: ProjectId = saved.project.parse().unwrap();
    let retained = trust
        .load(ProjectTrustProjectId::from_bytes(project.into_bytes()))
        .unwrap();
    assert_eq!(retained, saved.trust_record());
    assert_eq!(retained.token(), saved.trust_record().token());
    assert_eq!(std::fs::read(saved.marker(root)).unwrap(), b"once");
    assert_eq!(paths::read::<RequestRecord>(root, "request.json"), request);
    drop(prepared);
    drop(owner);
    assert_eq!(
        Rows::read(
            &observations::reader(root, saved),
            saved.identity().taskrun_id
        ),
        before
    );
}
