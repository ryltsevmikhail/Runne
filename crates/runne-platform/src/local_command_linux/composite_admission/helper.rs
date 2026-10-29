use super::support::{MAX_SCOPE_LIFETIME_MS, random_handle, workspace_identity};
use super::{LinuxCompositeScopeAdmission, PendingAdmission, PendingAdmissionKind};
use crate::local_command_linux::{
    LinuxCommandError, child::composite::PreparedComposite,
    permission::PermissionHelperOperationV1, snapshot::SealedExecutableSnapshot,
};
use runne_application::permission_modes::{
    CompositeEffectScope, ContainmentStrategy, FilesystemPosture, IntegrityDigest,
    NativeAdmissionError, NativeScopeAdmissionPort, NativeScopeAdmissionReceipt, PermissionMode,
};
use sha2::{Digest, Sha256};
use std::{fs::File, time::Instant};

#[path = "helper_readiness.rs"]
mod helper_readiness;
#[path = "helper_scope.rs"]
mod helper_scope;
use helper_scope::helper_operation_from_scope;

impl LinuxCompositeScopeAdmission {
    pub(in crate::local_command_linux) fn helper_admission_port(
        &self,
    ) -> impl NativeScopeAdmissionPort + '_ {
        ToolHelperAdmissionPort { owner: self }
    }

    pub(in crate::local_command_linux) fn helper_image(
        &self,
    ) -> Result<&SealedExecutableSnapshot, LinuxCommandError> {
        self.helper_executable
            .as_ref()
            .ok_or(LinuxCommandError::Unavailable)
    }

    pub(in crate::local_command_linux) fn bind_helper_request(
        &self,
        scope: &CompositeEffectScope,
        receipt: NativeScopeAdmissionReceipt,
        operation: PermissionHelperOperationV1,
        request_digest: [u8; 32],
        workspace: &File,
        cwd: &File,
    ) -> Result<(), LinuxCommandError> {
        self.validate_helper_scope(scope, operation)?;
        let digest = scope.digest().map_err(|_| LinuxCommandError::Unverified)?;
        if receipt.scope_digest() != digest
            || receipt.managed_policy_digest() != scope.managed_policy.policy_digest()
            || receipt.containment() != ContainmentStrategy::WorkspaceBoundV1
        {
            return Err(LinuxCommandError::Unverified);
        }
        let mut pending = self.lock()?;
        let token = pending
            .get_mut(&receipt.platform_handle_id())
            .ok_or(LinuxCommandError::Unverified)?;
        if token.scope_digest != digest
            || token.managed_policy_digest != receipt.managed_policy_digest()
            || token.containment != ContainmentStrategy::WorkspaceBoundV1
            || token.kind != PendingAdmissionKind::HelperScope(operation.scope_operation())
            || token.admitted_at.elapsed() > std::time::Duration::from_millis(scope.lifetime_ms)
        {
            return Err(LinuxCommandError::Unverified);
        }
        let root_identity = helper_root_identity(scope).ok_or(LinuxCommandError::Unverified)?;
        if workspace_identity(workspace)? != root_identity {
            return Err(LinuxCommandError::Unverified);
        }
        token.prepared.validate_workspace_bound(workspace, cwd)?;
        token.kind = PendingAdmissionKind::HelperRequest {
            operation,
            request_digest,
        };
        Ok(())
    }

    pub(in crate::local_command_linux) fn consume_helper_request(
        &self,
        scope: &CompositeEffectScope,
        receipt: NativeScopeAdmissionReceipt,
        operation: PermissionHelperOperationV1,
        request_digest: [u8; 32],
        workspace: &File,
        cwd: &File,
    ) -> Result<(PreparedComposite, Instant), LinuxCommandError> {
        self.validate_helper_scope(scope, operation)?;
        let digest = scope.digest().map_err(|_| LinuxCommandError::Unverified)?;
        if receipt.scope_digest() != digest
            || receipt.managed_policy_digest() != scope.managed_policy.policy_digest()
            || receipt.containment() != ContainmentStrategy::WorkspaceBoundV1
        {
            return Err(LinuxCommandError::Unverified);
        }
        let mut pending = self.lock()?;
        let key = receipt.platform_handle_id();
        {
            let token = pending.get(&key).ok_or(LinuxCommandError::Unverified)?;
            if token.scope_digest != digest
                || token.managed_policy_digest != receipt.managed_policy_digest()
                || token.containment != ContainmentStrategy::WorkspaceBoundV1
                || token.kind
                    != (PendingAdmissionKind::HelperRequest {
                        operation,
                        request_digest,
                    })
                || token.admitted_at.elapsed() > std::time::Duration::from_millis(scope.lifetime_ms)
            {
                return Err(LinuxCommandError::Unverified);
            }
            let root_identity = helper_root_identity(scope).ok_or(LinuxCommandError::Unverified)?;
            if workspace_identity(workspace)? != root_identity {
                return Err(LinuxCommandError::Unverified);
            }
            token.prepared.validate_workspace_bound(workspace, cwd)?;
        }
        let consumed = pending.remove(&key).ok_or(LinuxCommandError::Unverified)?;
        Ok((consumed.prepared, consumed.admitted_at))
    }

    fn admit_helper_scope(
        &self,
        scope: &CompositeEffectScope,
        operation: PermissionHelperOperationV1,
    ) -> Result<IntegrityDigest, LinuxCommandError> {
        self.validate_helper_scope(scope, operation)?;
        let roots = self.roots.iter().collect::<Vec<_>>();
        let prepared = PreparedComposite::admit(&roots)?;
        let scope_digest = scope.digest().map_err(|_| LinuxCommandError::Unverified)?;
        let root_identity = helper_root_identity(scope).ok_or(LinuxCommandError::Unverified)?;
        let handle = random_handle()?;
        let mut pending = self.lock()?;
        pending.retain(|_, token| {
            token.admitted_at.elapsed().as_millis() <= u128::from(MAX_SCOPE_LIFETIME_MS)
        });
        if pending.len() >= super::MAX_PENDING_ADMISSIONS || pending.contains_key(&handle) {
            return Err(LinuxCommandError::Unavailable);
        }
        pending.insert(
            handle,
            PendingAdmission {
                scope_digest,
                managed_policy_digest: scope.managed_policy.policy_digest(),
                containment: scope.containment,
                prepared,
                workspace_root: Some(root_identity),
                network_none: true,
                admitted_at: Instant::now(),
                kind: PendingAdmissionKind::HelperScope(operation),
            },
        );
        Ok(handle)
    }
}

struct ToolHelperAdmissionPort<'a> {
    owner: &'a LinuxCompositeScopeAdmission,
}

impl NativeScopeAdmissionPort for ToolHelperAdmissionPort<'_> {
    fn admit_mode_readiness(
        &self,
        mode: PermissionMode,
        scope: &CompositeEffectScope,
    ) -> Result<IntegrityDigest, runne_application::permission_modes::NativeAdmissionError> {
        if mode == PermissionMode::FullAccess
            && let Some(canonical_scope) = helper_readiness::translate_full_access_scope(
                scope,
                self.owner.protected_policy_digest,
                self.owner.protected_policy_digest_v2_broad,
            )
        {
            return helper_readiness::admit_full_access(self.owner, scope, &canonical_scope);
        }
        let Some(operation) = helper_operation_from_scope(scope) else {
            return NativeScopeAdmissionPort::admit_mode_readiness(self.owner, mode, scope);
        };
        if self.owner.validate_helper_scope(scope, operation).is_err() {
            return NativeScopeAdmissionPort::admit_mode_readiness(self.owner, mode, scope);
        }
        self.preflight_helper_native(scope)?;
        if mode == PermissionMode::FullAccess {
            return Err(NativeAdmissionError::CompositePolicyUnenforceable);
        }
        let scope_digest = scope
            .digest()
            .map_err(|_| NativeAdmissionError::CompositePolicyUnenforceable)?;
        let mut hash = Sha256::new();
        hash.update(b"runne:d21:linux-helper-readiness:v1\0");
        hash.update([match mode {
            PermissionMode::AskAlways => 1,
            PermissionMode::RiskBased => 2,
            PermissionMode::FullAccess => 3,
        }]);
        hash.update(scope_digest.as_bytes());
        hash.update(scope.protected_control_plane_policy_digest.as_bytes());
        Ok(IntegrityDigest::from_bytes(hash.finalize().into()))
    }

    fn admit_scope(
        &self,
        scope: &CompositeEffectScope,
    ) -> Result<IntegrityDigest, runne_application::permission_modes::NativeAdmissionError> {
        let operation = helper_operation_from_scope(scope)
            .ok_or(NativeAdmissionError::CompositePolicyUnenforceable)?;
        self.owner
            .validate_helper_scope(scope, operation)
            .map_err(|_| NativeAdmissionError::CompositePolicyUnenforceable)?;
        self.preflight_helper_native(scope)?;
        self.owner
            .admit_helper_scope(scope, operation)
            .map_err(|_| NativeAdmissionError::EnforcementUnavailable)
    }
}

impl ToolHelperAdmissionPort<'_> {
    fn preflight_helper_native(
        &self,
        scope: &CompositeEffectScope,
    ) -> Result<(), runne_application::permission_modes::NativeAdmissionError> {
        let helper_image = self
            .owner
            .helper_image()
            .map_err(|_| NativeAdmissionError::EnforcementUnavailable)?;
        helper_image
            .validate_seals()
            .map_err(|_| NativeAdmissionError::EnforcementUnavailable)?;
        let mut filesystem = super::super::policy::native_fs_profile(&scope.filesystem.permissions)
            .map_err(|_| NativeAdmissionError::CompositePolicyUnenforceable)?;
        filesystem.metadata_allowed = false;
        super::super::policy::preflight_composite_ruleset(filesystem)
            .map_err(|_| NativeAdmissionError::EnforcementUnavailable)?;
        if super::super::gate::prepare_seccomp(
            scope.children == runne_application::permission_modes::ChildDelegationScope::Unbounded,
            true,
            Some(filesystem),
        )
        .is_none()
        {
            return Err(NativeAdmissionError::EnforcementUnavailable);
        }
        Ok(())
    }
}

fn helper_root_identity(scope: &CompositeEffectScope) -> Option<IntegrityDigest> {
    match &scope.filesystem.posture {
        FilesystemPosture::BoundedRoots(roots) if roots.len() == 1 => {
            roots.iter().next().map(|root| root.root_identity)
        }
        _ => None,
    }
}
