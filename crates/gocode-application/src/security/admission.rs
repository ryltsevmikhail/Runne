//! Совместная fail-closed admission-проверка capability, budget, sandbox и fence.

use gocode_domain::security::{AuthEpoch, Generation, GrantId};

use super::{
    error::SecurityError,
    grant::CapabilityGrant,
    ports::{CapabilityEngine, CapabilityRequest},
};

pub trait BudgetManager: Send + Sync {
    fn reserve(&self, dimension: &str, amount: u64) -> Result<String, SecurityError>;
}

pub trait SandboxManager: Send + Sync {
    fn bind_invocation(&self, grant: &CapabilityGrant) -> Result<String, SecurityError>;
}

pub trait FencingManager: Send + Sync {
    fn current_generation(&self, owner: &str) -> Result<Generation, SecurityError>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdmissionRequest {
    pub capability: CapabilityRequest,
    pub budget_dimension: String,
    pub budget_amount: u64,
    pub fence_owner: String,
    pub generation: Generation,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdmissionPermit {
    pub grant_id: GrantId,
    pub budget_reservation: String,
    pub sandbox_permit: String,
    pub auth_epoch: AuthEpoch,
    pub generation: Generation,
    pub fence_owner: String,
}

pub struct AdmissionManager<C, B, S, F> {
    capability_engine: C,
    budget_manager: B,
    sandbox_manager: S,
    fencing_manager: F,
}

impl<C, B, S, F> AdmissionManager<C, B, S, F>
where
    C: CapabilityEngine,
    B: BudgetManager,
    S: SandboxManager,
    F: FencingManager,
{
    pub fn new(
        capability_engine: C,
        budget_manager: B,
        sandbox_manager: S,
        fencing_manager: F,
    ) -> Self {
        Self {
            capability_engine,
            budget_manager,
            sandbox_manager,
            fencing_manager,
        }
    }

    pub fn check(&self, request: &AdmissionRequest) -> Result<AdmissionPermit, SecurityError> {
        let grant = self.capability_engine.evaluate(&request.capability)?;
        let reservation = self
            .budget_manager
            .reserve(&request.budget_dimension, request.budget_amount)?;
        let sandbox_permit = self.sandbox_manager.bind_invocation(&grant)?;
        if self
            .fencing_manager
            .current_generation(&request.fence_owner)?
            != request.generation
        {
            return Err(SecurityError::StaleGeneration);
        }
        Ok(AdmissionPermit {
            grant_id: grant.grant_id,
            budget_reservation: reservation,
            sandbox_permit,
            auth_epoch: grant.auth_epoch,
            generation: request.generation,
            fence_owner: request.fence_owner.clone(),
        })
    }

    pub fn recheck_at_boundary(&self, permit: &AdmissionPermit) -> Result<(), SecurityError> {
        if self
            .fencing_manager
            .current_generation(&permit.fence_owner)?
            != permit.generation
        {
            return Err(SecurityError::StaleGeneration);
        }
        Ok(())
    }
}
