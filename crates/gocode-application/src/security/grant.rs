//! Неизменяемые capability grants и их scope/constraints.

use gocode_domain::{
    id::{AttemptId, InvocationId, TaskRunId, WorkspaceId},
    security::{AuthEpoch, CanonicalAction, GrantId, NormalizedResource, PrincipalIdentity},
    timestamp::Timestamp,
};

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct GrantConstraints {
    /// Дополнительные обязательные ограничения в канонической форме.
    pub required: Vec<String>,
    /// Максимум использований; `None` означает отсутствие данного ограничения.
    pub max_uses: Option<u64>,
}

impl GrantConstraints {
    pub fn is_at_least_as_strict_as(&self, parent: &Self) -> bool {
        parent
            .required
            .iter()
            .all(|required| self.required.contains(required))
            && match (parent.max_uses, self.max_uses) {
                (None, _) => true,
                (Some(_), None) => false,
                (Some(parent), Some(child)) => child <= parent,
            }
    }

    pub fn covers(&self, requested: &Self) -> bool {
        requested.is_at_least_as_strict_as(self)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct GrantScope {
    pub tenant_id: Option<String>,
    pub project_id: Option<String>,
    pub workspace_id: Option<WorkspaceId>,
    pub task_run_id: Option<TaskRunId>,
    pub attempt_id: Option<AttemptId>,
    pub invocation_id: Option<InvocationId>,
}

impl GrantScope {
    pub fn contains(&self, request: &Self) -> bool {
        contains_dimension(&self.tenant_id, &request.tenant_id)
            && contains_dimension(&self.project_id, &request.project_id)
            && contains_dimension(&self.workspace_id, &request.workspace_id)
            && contains_dimension(&self.task_run_id, &request.task_run_id)
            && contains_dimension(&self.attempt_id, &request.attempt_id)
            && contains_dimension(&self.invocation_id, &request.invocation_id)
    }

    pub fn is_subset_of(&self, parent: &Self) -> bool {
        parent.contains(self)
    }
}

fn contains_dimension<T: PartialEq>(grant: &Option<T>, request: &Option<T>) -> bool {
    match grant {
        None => true,
        Some(value) => request.as_ref() == Some(value),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapabilityGrant {
    pub grant_id: GrantId,
    pub subject: PrincipalIdentity,
    pub issuer: PrincipalIdentity,
    pub action: CanonicalAction,
    pub resource: NormalizedResource,
    pub constraints: GrantConstraints,
    pub scope: GrantScope,
    pub expires_at: Timestamp,
    pub delegation_limit: u32,
    pub policy_revision: u64,
    pub auth_epoch: AuthEpoch,
    pub audit_correlation: String,
    pub issued_at: Timestamp,
}

impl CapabilityGrant {
    pub fn is_expired(&self, now: Timestamp) -> bool {
        self.expires_at < now
    }

    pub fn covers_action(&self, action: &CanonicalAction) -> bool {
        &self.action == action
    }

    pub fn covers_resource(&self, resource: &NormalizedResource) -> bool {
        self.resource == *resource
            || (self.resource.as_str().ends_with('/')
                && resource.as_str().starts_with(self.resource.as_str()))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GrantLifecycleState {
    Issued,
    Active,
    Expired,
    Revoked,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GrantLifecycle {
    pub grant_id: GrantId,
    pub state: GrantLifecycleState,
    pub version: u64,
}
