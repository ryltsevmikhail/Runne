//! Opaque closed six-class managed-policy evidence for composite V2 scopes.

#[path = "closed_coverage/model.rs"]
mod model;

pub use model::ClosedManagedCoverageV1;

impl super::ManagedPolicyCoverage {
    /// Recomputes fixed V2 evidence from a project identifier and policy snapshot.
    pub fn from_closed_snapshot(
        project: crate::project_trust::ProjectTrustProjectId,
        snapshot: &crate::project_trust::ProjectTrustEffectPolicySnapshot,
    ) -> Option<Self> {
        ClosedManagedCoverageV1::from_snapshot(project, snapshot).map(Self::Closed)
    }

    /// Checks whether opaque closed evidence has a supported scope mapping.
    pub fn supports_closed_scope(&self, scope: &super::CompositeEffectScope) -> bool {
        matches!(self, Self::Closed(coverage) if coverage.supports_scope(scope))
    }

    /// Checks canonical scope shape without consulting Allow/Ask/Deny decisions.
    pub fn supports_scope_shape(&self, scope: &super::CompositeEffectScope) -> bool {
        matches!(self, Self::Closed(coverage) if coverage.supports_scope_shape(scope))
    }

    /// Lowest decision among classes the exact scope actually provides.
    pub fn scope_minimum_disposition(
        &self,
        scope: &super::CompositeEffectScope,
    ) -> Option<crate::project_trust::ManagedEffectDecision> {
        match self {
            Self::Closed(coverage) => Some(coverage.scope_minimum_disposition(scope)),
            _ => None,
        }
    }
}

#[cfg(test)]
#[path = "closed_coverage/tests.rs"]
mod tests;

#[cfg(test)]
#[path = "closed_coverage/tests_budget.rs"]
mod tests_budget;

#[cfg(test)]
#[path = "closed_coverage/tests_shape_policy.rs"]
mod tests_shape_policy;

#[cfg(test)]
#[path = "closed_coverage/tests_partial_rights.rs"]
mod tests_partial_rights;

#[cfg(test)]
#[path = "closed_coverage/tests_partial_support.rs"]
mod tests_partial_support;
