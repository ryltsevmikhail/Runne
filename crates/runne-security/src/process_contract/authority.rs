//! Shared authorization state and transactional lifecycle fencing.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};

use runne_platform_ports::process::{
    ProcessLifecycleBindingV1, VerifiedCwdV1, VerifiedExecutableV1,
};

use super::authorization::{AuthorizationReplayDomainV1, AuthorizationReplayGuard};
use super::boundary::ProcessAuthorizationBoundaryV1;
use super::context::CurrentProcessContextV1;
use super::{
    AllowedRootId, ApproverId, AuthorityId, CapabilityGrantId, ExecutablePolicyId, PrincipalId,
    ProcessContractError, ProcessIdentityBindingV1, SandboxId,
};

static NEXT_AUTHORITY_INSTANCE: AtomicU64 = AtomicU64::new(0);

struct ContextSeedV1 {
    executable: VerifiedExecutableV1,
    policy: ExecutablePolicyId,
    cwd: VerifiedCwdV1,
    root: AllowedRootId,
    principal: PrincipalId,
    authority: AuthorityId,
    accounting: CapabilityGrantId,
    sandbox: SandboxId,
    approver: ApproverId,
}

impl ContextSeedV1 {
    fn current(
        &self,
        lifecycle: ProcessLifecycleBindingV1,
        revision: u64,
        epoch: u64,
    ) -> CurrentProcessContextV1 {
        let binding = ProcessIdentityBindingV1::new(
            self.principal.clone(),
            self.authority.clone(),
            lifecycle.owner().clone(),
            lifecycle.attempt().clone(),
            lifecycle.session().clone(),
            lifecycle.generation().clone(),
            self.accounting.clone(),
            self.sandbox.clone(),
            lifecycle.tree_handle().clone(),
        );
        CurrentProcessContextV1::new(
            self.executable.clone(),
            self.policy.clone(),
            self.cwd.clone(),
            self.root.clone(),
            binding,
            self.approver.clone(),
            revision,
            epoch,
        )
    }
}

pub(super) struct ProcessAuthorizationStateV1 {
    context_seed: ContextSeedV1,
    pub(super) replay_guard: AuthorizationReplayGuard,
    pub(super) capability_counter: u64,
    pub(super) revision: u64,
    pub(super) epoch: u64,
}

/// Shared authority for independently bound exact process calls.
#[derive(Clone)]
pub struct ProcessAuthorizationAuthorityV1 {
    state: Arc<Mutex<ProcessAuthorizationStateV1>>,
}

impl ProcessAuthorizationAuthorityV1 {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        executable: VerifiedExecutableV1,
        policy: ExecutablePolicyId,
        cwd: VerifiedCwdV1,
        root: AllowedRootId,
        principal: PrincipalId,
        authority: AuthorityId,
        accounting: CapabilityGrantId,
        sandbox: SandboxId,
        approver: ApproverId,
        revision: u64,
        epoch: u64,
        replay_guard_id: [u8; 16],
    ) -> Result<Self, ProcessContractError> {
        let domain = AuthorizationReplayDomainV1::new(replay_guard_id, next_authority_instance()?);
        Ok(Self {
            state: Arc::new(Mutex::new(ProcessAuthorizationStateV1 {
                context_seed: ContextSeedV1 {
                    executable,
                    policy,
                    cwd,
                    root,
                    principal,
                    authority,
                    accounting,
                    sandbox,
                    approver,
                },
                replay_guard: AuthorizationReplayGuard::new(domain),
                capability_counter: 0,
                revision,
                epoch,
            })),
        })
    }

    pub fn bind_call(
        &self,
        lifecycle: ProcessLifecycleBindingV1,
    ) -> Result<ProcessAuthorizationBoundaryV1, ProcessContractError> {
        let state = self.lock()?;
        Ok(ProcessAuthorizationBoundaryV1::bound(
            self.clone(),
            state
                .context_seed
                .current(lifecycle, state.revision, state.epoch),
        ))
    }

    pub fn prepare_advance(
        &self,
    ) -> Result<ProcessAuthorizationAdvanceV1<'_>, ProcessContractError> {
        let state = self.lock()?;
        let next_revision = state
            .revision
            .checked_add(1)
            .ok_or(ProcessContractError::CapabilityInvalid)?;
        let next_epoch = state
            .epoch
            .checked_add(1)
            .ok_or(ProcessContractError::CapabilityInvalid)?;
        Ok(ProcessAuthorizationAdvanceV1 {
            state,
            next_revision,
            next_epoch,
            applied: false,
        })
    }

    pub(super) fn lock_for(
        &self,
        context: &CurrentProcessContextV1,
    ) -> Result<MutexGuard<'_, ProcessAuthorizationStateV1>, ProcessContractError> {
        let state = self.lock()?;
        if state.revision != context.revision || state.epoch != context.epoch {
            return Err(ProcessContractError::CapabilityInvalid);
        }
        Ok(state)
    }

    fn lock(&self) -> Result<MutexGuard<'_, ProcessAuthorizationStateV1>, ProcessContractError> {
        self.state
            .lock()
            .map_err(|_| ProcessContractError::CapabilityInvalid)
    }

    #[cfg(test)]
    pub(super) fn set_state_for_test(&self, revision: u64, epoch: u64, counter: u64) {
        let mut state = self.state.lock().expect("test authority lock");
        state.revision = revision;
        state.epoch = epoch;
        state.capability_counter = counter;
    }

    #[cfg(test)]
    pub(super) fn state_for_test(&self) -> (u64, u64, u64) {
        let state = self.state.lock().expect("test authority lock");
        (state.revision, state.epoch, state.capability_counter)
    }
}

fn next_authority_instance() -> Result<u64, ProcessContractError> {
    let previous = NEXT_AUTHORITY_INSTANCE
        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
            current.checked_add(1)
        })
        .map_err(|_| ProcessContractError::CapabilityInvalid)?;
    previous
        .checked_add(1)
        .ok_or(ProcessContractError::CapabilityInvalid)
}

/// Exclusive, abort-on-drop lifecycle revision prepared from an authority.
pub struct ProcessAuthorizationAdvanceV1<'a> {
    state: MutexGuard<'a, ProcessAuthorizationStateV1>,
    next_revision: u64,
    next_epoch: u64,
    applied: bool,
}

impl ProcessAuthorizationAdvanceV1<'_> {
    /// Applies this prepared revision while retaining the authorization mutex.
    pub fn apply_retaining_lock(&mut self) {
        if !self.applied {
            self.state.revision = self.next_revision;
            self.state.epoch = self.next_epoch;
            self.applied = true;
        }
    }

    /// Applies this prepared revision and releases the authorization mutex.
    pub fn commit(mut self) -> Result<(), ProcessContractError> {
        self.apply_retaining_lock();
        Ok(())
    }
}
