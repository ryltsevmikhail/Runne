use super::{LinuxCommandError, child::composite::PreparedComposite};
use runne_application::permission_modes::{
    CompositeEffectScope, CompositeScopeDigest, ContainmentStrategy, FilesystemPosture,
    IntegrityDigest, NativeAdmissionError, NativeScopeAdmissionPort, NativeScopeAdmissionReceipt,
    NetworkScope, PermissionMode,
};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs::File;
use std::sync::Mutex;
use std::time::Instant;
#[path = "composite_admission/support.rs"]
mod support;
use support::{MAX_SCOPE_LIFETIME_MS, random_handle, validate_scope, workspace_identity};

const MAX_PENDING_ADMISSIONS: usize = 256;

struct PendingAdmission {
    scope_digest: CompositeScopeDigest,
    managed_policy_digest: IntegrityDigest,
    containment: ContainmentStrategy,
    prepared: PreparedComposite,
    workspace_root: Option<IntegrityDigest>,
    network_none: bool,
    admitted_at: Instant,
}

/// Runtime-owned registry of held reserved-root descriptors and one-shot scope tokens.
pub struct LinuxCompositeScopeAdmission {
    roots: Vec<File>,
    protected_policy_digest: IntegrityDigest,
    pending: Mutex<HashMap<IntegrityDigest, PendingAdmission>>,
}

impl LinuxCompositeScopeAdmission {
    /// Holds and validates the protected roots that scope construction must bind.
    pub fn new(protected_roots: &[&File]) -> Result<Self, LinuxCommandError> {
        let roots = protected_roots
            .iter()
            .map(|root| root.try_clone().map_err(|_| LinuxCommandError::Unavailable))
            .collect::<Result<Vec<_>, _>>()?;
        let references = roots.iter().collect::<Vec<_>>();
        let prepared = PreparedComposite::admit(&references)?;
        let protected_policy_digest = PreparedComposite::protected_policy_digest(&references)?;
        drop(prepared);
        Ok(Self {
            roots,
            protected_policy_digest,
            pending: Mutex::new(HashMap::new()),
        })
    }

    /// Digest to place in `CompositeEffectScope` before asking this port to admit it.
    #[must_use]
    pub const fn protected_control_plane_policy_digest(&self) -> IntegrityDigest {
        self.protected_policy_digest
    }

    /// Canonical descriptor identity for a workspace root in `FilesystemRoot`.
    pub fn workspace_root_identity(workspace: &File) -> Result<IntegrityDigest, LinuxCommandError> {
        workspace_identity(workspace)
    }

    /// Explicitly discards an unused admission receipt and its held tree snapshot.
    pub fn revoke(&self, receipt: NativeScopeAdmissionReceipt) -> Result<bool, LinuxCommandError> {
        Ok(self.lock()?.remove(&receipt.platform_handle_id()).is_some())
    }

    pub(super) fn inspect(
        &self,
        scope: &CompositeEffectScope,
        receipt: NativeScopeAdmissionReceipt,
        workspace: &File,
        cwd: &File,
        consume: bool,
    ) -> Result<(Option<PreparedComposite>, bool), LinuxCommandError> {
        validate_scope(scope, self.protected_policy_digest)
            .map_err(|_| LinuxCommandError::CompositePolicyUnenforceable)?;
        let digest = scope
            .digest()
            .map_err(|_| LinuxCommandError::CompositePolicyUnenforceable)?;
        if receipt.scope_digest() != digest
            || receipt.managed_policy_digest() != scope.managed_policy.policy_digest()
            || receipt.containment() != scope.containment
        {
            return Err(LinuxCommandError::Unverified);
        }
        let mut pending = self.lock()?;
        let key = receipt.platform_handle_id();
        let token = pending.get(&key).ok_or(LinuxCommandError::Unverified)?;
        if token.scope_digest != digest
            || token.managed_policy_digest != receipt.managed_policy_digest()
            || token.containment != receipt.containment()
            || token.admitted_at.elapsed().as_millis() > u128::from(MAX_SCOPE_LIFETIME_MS)
        {
            return Err(LinuxCommandError::Unverified);
        }
        let result = match token.workspace_root {
            Some(expected) if workspace_identity(workspace)? == expected => {
                if scope.containment != ContainmentStrategy::WorkspaceBoundV1 {
                    return Err(LinuxCommandError::Unverified);
                }
                token.prepared.validate_workspace_bound(workspace, cwd)?;
                Ok((None, true))
            }
            Some(_) => Err(LinuxCommandError::Unverified),
            None => {
                if scope.containment != ContainmentStrategy::SameUserCompositeV1 {
                    return Err(LinuxCommandError::Unverified);
                }
                let prepared = token.prepared.validate_for(workspace, cwd)?;
                Ok((Some(prepared), token.network_none))
            }
        }?;
        if consume {
            pending.remove(&key);
        }
        Ok(result)
    }

    fn lock(
        &self,
    ) -> Result<
        std::sync::MutexGuard<'_, HashMap<IntegrityDigest, PendingAdmission>>,
        LinuxCommandError,
    > {
        self.pending
            .lock()
            .map_err(|_| LinuxCommandError::Unverified)
    }
}

impl NativeScopeAdmissionPort for LinuxCompositeScopeAdmission {
    fn admit_mode_readiness(
        &self,
        mode: PermissionMode,
        scope: &CompositeEffectScope,
    ) -> Result<IntegrityDigest, NativeAdmissionError> {
        scope
            .validate()
            .map_err(|_| NativeAdmissionError::CompositePolicyUnenforceable)?;
        if scope.protected_control_plane_policy_digest != self.protected_policy_digest {
            return Err(NativeAdmissionError::CompositePolicyUnenforceable);
        }
        if mode == PermissionMode::FullAccess {
            if scope.containment != ContainmentStrategy::SameUserCompositeV1
                || !matches!(scope.filesystem.posture, FilesystemPosture::BroadSameUser)
                || scope.network != NetworkScope::BroadSameUser
            {
                return Err(NativeAdmissionError::CompositePolicyUnenforceable);
            }
            let roots = self.roots.iter().collect::<Vec<_>>();
            PreparedComposite::admit(&roots)
                .and_then(|_| PreparedComposite::preflight_namespaces())
                .map_err(|_| NativeAdmissionError::EnforcementUnavailable)?;
        }
        let scope_digest = scope
            .digest()
            .map_err(|_| NativeAdmissionError::CompositePolicyUnenforceable)?;
        let mut hash = Sha256::new();
        hash.update(b"runne:d21:linux-mode-readiness:v1\0");
        hash.update([match mode {
            PermissionMode::AskAlways => 1,
            PermissionMode::RiskBased => 2,
            PermissionMode::FullAccess => 3,
        }]);
        hash.update(scope_digest.as_bytes());
        hash.update(self.protected_policy_digest.as_bytes());
        let handle = IntegrityDigest::from_bytes(hash.finalize().into());
        if handle.as_bytes().iter().all(|byte| *byte == 0) {
            Err(NativeAdmissionError::EnforcementUnavailable)
        } else {
            Ok(handle)
        }
    }

    fn admit_scope(
        &self,
        scope: &CompositeEffectScope,
    ) -> Result<IntegrityDigest, NativeAdmissionError> {
        validate_scope(scope, self.protected_policy_digest)
            .map_err(|_| NativeAdmissionError::CompositePolicyUnenforceable)?;
        let roots = self.roots.iter().collect::<Vec<_>>();
        let prepared = PreparedComposite::admit(&roots)
            .map_err(|_| NativeAdmissionError::EnforcementUnavailable)?;
        if scope.containment == ContainmentStrategy::SameUserCompositeV1 {
            PreparedComposite::preflight_namespaces()
                .map_err(|_| NativeAdmissionError::EnforcementUnavailable)?;
        }
        let scope_digest = scope
            .digest()
            .map_err(|_| NativeAdmissionError::CompositePolicyUnenforceable)?;
        let workspace_root = match &scope.filesystem.posture {
            FilesystemPosture::BoundedRoots(roots) => {
                roots.iter().next().map(|root| root.root_identity)
            }
            _ => None,
        };
        let handle = random_handle().map_err(|_| NativeAdmissionError::EnforcementUnavailable)?;
        let mut pending = self
            .pending
            .lock()
            .map_err(|_| NativeAdmissionError::EnforcementUnavailable)?;
        pending.retain(|_, token| {
            token.admitted_at.elapsed().as_millis() <= u128::from(MAX_SCOPE_LIFETIME_MS)
        });
        if pending.len() >= MAX_PENDING_ADMISSIONS || pending.contains_key(&handle) {
            return Err(NativeAdmissionError::EnforcementUnavailable);
        }
        pending.insert(
            handle,
            PendingAdmission {
                scope_digest,
                managed_policy_digest: scope.managed_policy.policy_digest(),
                containment: scope.containment,
                prepared,
                workspace_root,
                network_none: scope.network == NetworkScope::None,
                admitted_at: Instant::now(),
            },
        );
        Ok(handle)
    }
}
