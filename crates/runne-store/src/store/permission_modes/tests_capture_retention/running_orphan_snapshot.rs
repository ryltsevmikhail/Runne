//! Durable snapshot while the closed fixture writer is quiescent.
//! SELECT assertions do not prove physical aliveness; use real live samples too.
use super::{
    attempt::{self, Attempt},
    context::CaseContext,
    metadata::Area,
    observations::{self, Spent},
    workspace,
};
use crate::{
    ProjectTrustStore,
    store::{LocalCommandAttemptState, StoreTransaction},
};
use runne_application::project_trust::{ProjectTrustPersistence, ProjectTrustProjectId};
use runne_domain::{id::ProjectId, task_run::TaskRunState};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Running {
    pub attempt: Attempt,
    pub spent: Spent,
    pub stream_version: u64,
    pub event_ids: Vec<Vec<u8>>,
}

impl Running {
    pub(super) fn validate(&self, area: &Area) {
        self.attempt.validate(area, "running");
        self.spent.assert_original(area);
        assert!(self.stream_version > 0);
        assert!(!self.event_ids.is_empty() && self.event_ids.len() <= 128);
        let mut unique = BTreeSet::new();
        for bytes in &self.event_ids {
            let id: [u8; 16] = bytes.as_slice().try_into().unwrap();
            runne_domain::id::validate_uuid_v7_bytes(&id).unwrap();
            assert!(unique.insert(id));
        }
    }
}

fn rows(context: &CaseContext, area: &Area) -> (Attempt, Spent) {
    let reader = observations::reader(context, area);
    observations::attempt(&reader, area, "running");
    observations::no_factual_terminal_or_provider(&reader, area);
    observations::count(&reader, "taskrun_terminal_settlement_receipts", area, 0);
    observations::count(&reader, "taskrun_local_command_stop_receipts", area, 0);
    (
        attempt::observe(&reader, area, "running"),
        observations::spent(&reader, area),
    )
}

pub(super) fn observe(
    context: &CaseContext,
    area: &Area,
    store: &StoreTransaction,
    trust: &ProjectTrustStore,
) -> Running {
    area.validate(context);
    let project: ProjectId = area.project.parse().unwrap();
    let project = ProjectTrustProjectId::from_bytes(project.into_bytes());
    let token = area.trust_record();
    assert_eq!(trust.load(project).unwrap(), token);
    assert_eq!(trust.load(project).unwrap().token(), token.token());
    workspace::pending(context, area);
    observations::capture(store, area, LocalCommandAttemptState::Running);
    let before = observations::stream(store, area, TaskRunState::Running);
    let (attempt, spent) = rows(context, area);
    let after = observations::stream(store, area, TaskRunState::Running);
    assert_eq!(before, after);
    assert_eq!(rows(context, area), (attempt.clone(), spent.clone()));
    observations::capture(store, area, LocalCommandAttemptState::Running);
    assert_eq!(trust.load(project).unwrap(), token);
    assert_eq!(trust.load(project).unwrap().token(), token.token());
    workspace::pending(context, area);
    let value = Running {
        attempt,
        spent,
        stream_version: before.0,
        event_ids: before.1,
    };
    value.validate(area);
    context.deadline.check();
    value
}
