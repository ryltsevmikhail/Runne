use super::*;
use runne_application::permission_modes::{
    FilesystemPosture, NativeAdmissionError, NativeScopeAdmissionPort, PermissionMode,
};

impl LinuxCompositeScopeAdmission {
    /// Network-specific protected identity for closed V2 composite scopes.
    pub fn protected_control_plane_policy_digest_v2(
        &self,
        network: NetworkScope,
    ) -> Result<IntegrityDigest, LinuxCommandError> {
        match network {
            NetworkScope::BroadSameUser => Ok(self.protected_policy_digest_v2_broad),
            NetworkScope::None => Ok(self.protected_policy_digest_v2_none),
            _ => Err(LinuxCommandError::CompositePolicyUnenforceable),
        }
    }

    /// Protected identity for exact partial-rights V2 profiles.
    pub fn protected_control_plane_policy_digest_v3(
        &self,
        network: NetworkScope,
    ) -> Result<IntegrityDigest, LinuxCommandError> {
        match network {
            NetworkScope::BroadSameUser => Ok(self.protected_policy_digest_v3_broad),
            NetworkScope::None => Ok(self.protected_policy_digest_v3_none),
            _ => Err(LinuxCommandError::CompositePolicyUnenforceable),
        }
    }

    /// Canonical descriptor identity for a workspace root in `FilesystemRoot`.
    pub fn workspace_root_identity(workspace: &File) -> Result<IntegrityDigest, LinuxCommandError> {
        support::workspace_identity(workspace)
    }

    /// Explicitly discards an unused admission receipt and its held tree snapshot.
    pub fn revoke(&self, receipt: NativeScopeAdmissionReceipt) -> Result<bool, LinuxCommandError> {
        Ok(self.lock()?.remove(&receipt.platform_handle_id()).is_some())
    }

    pub(super) fn protected_identity(
        &self,
        scope: &CompositeEffectScope,
    ) -> Option<IntegrityDigest> {
        match (
            scope.containment,
            scope.managed_policy.is_closed(),
            scope.network,
        ) {
            (ContainmentStrategy::SameUserCompositeV2, true, NetworkScope::BroadSameUser) => {
                Some(self.protected_policy_digest_v3_broad)
            }
            (ContainmentStrategy::SameUserCompositeV2, true, NetworkScope::None) => {
                Some(self.protected_policy_digest_v3_none)
            }
            (ContainmentStrategy::SameUserCompositeV1, true, NetworkScope::BroadSameUser) => {
                Some(self.protected_policy_digest_v2_broad)
            }
            (ContainmentStrategy::SameUserCompositeV1, true, NetworkScope::None) => {
                Some(self.protected_policy_digest_v2_none)
            }
            (
                ContainmentStrategy::SameUserCompositeV1,
                false,
                NetworkScope::None | NetworkScope::BroadSameUser,
            ) => Some(self.protected_policy_digest),
            (ContainmentStrategy::WorkspaceBoundV1, false, NetworkScope::None) => {
                Some(self.protected_policy_digest)
            }
            _ => None,
        }
    }

    pub(super) fn lock(
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
        let protected = self
            .protected_identity(scope)
            .ok_or(NativeAdmissionError::CompositePolicyUnenforceable)?;
        if scope.protected_control_plane_policy_digest != protected {
            return Err(NativeAdmissionError::CompositePolicyUnenforceable);
        }
        let closed = scope.managed_policy.is_closed();
        if closed {
            validate_scope(scope, protected)
                .map_err(|_| NativeAdmissionError::CompositePolicyUnenforceable)?;
            let roots = self.roots.iter().collect::<Vec<_>>();
            PreparedComposite::admit(&roots)
                .and_then(|_| PreparedComposite::preflight_namespaces())
                .map_err(|_| NativeAdmissionError::EnforcementUnavailable)?;
            if scope.containment == ContainmentStrategy::SameUserCompositeV2 {
                let fs = super::super::policy::native_fs_profile(&scope.filesystem.permissions)
                    .map_err(|_| NativeAdmissionError::CompositePolicyUnenforceable)?;
                super::super::policy::preflight_composite_ruleset(fs)
                    .map_err(|_| NativeAdmissionError::EnforcementUnavailable)?;
            }
        }
        if mode == PermissionMode::FullAccess {
            let closed_ready = closed
                && matches!(
                    scope.network,
                    NetworkScope::BroadSameUser | NetworkScope::None
                );
            let legacy_ready = !closed && scope.network == NetworkScope::BroadSameUser;
            let strategy_ready = match scope.containment {
                ContainmentStrategy::SameUserCompositeV1 => true,
                ContainmentStrategy::SameUserCompositeV2 => closed,
                ContainmentStrategy::WorkspaceBoundV1 => false,
            };
            if !strategy_ready
                || !matches!(scope.filesystem.posture, FilesystemPosture::BroadSameUser)
                || !(closed_ready || legacy_ready)
            {
                return Err(NativeAdmissionError::CompositePolicyUnenforceable);
            }
            if !closed {
                let roots = self.roots.iter().collect::<Vec<_>>();
                PreparedComposite::admit(&roots)
                    .and_then(|_| PreparedComposite::preflight_namespaces())
                    .map_err(|_| NativeAdmissionError::EnforcementUnavailable)?;
            }
        }
        let scope_digest = scope
            .digest()
            .map_err(|_| NativeAdmissionError::CompositePolicyUnenforceable)?;
        let mut hash = Sha256::new();
        match scope.containment {
            ContainmentStrategy::SameUserCompositeV2 => {
                hash.update(b"runne:d21:linux-mode-readiness:v3\0")
            }
            _ if closed => hash.update(b"runne:d21:linux-mode-readiness:v2\0"),
            _ => hash.update(b"runne:d21:linux-mode-readiness:v1\0"),
        }
        hash.update([match mode {
            PermissionMode::AskAlways => 1,
            PermissionMode::RiskBased => 2,
            PermissionMode::FullAccess => 3,
        }]);
        hash.update(scope_digest.as_bytes());
        hash.update(scope.protected_control_plane_policy_digest.as_bytes());
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
        let protected = self
            .protected_identity(scope)
            .ok_or(NativeAdmissionError::CompositePolicyUnenforceable)?;
        validate_scope(scope, protected)
            .map_err(|_| NativeAdmissionError::CompositePolicyUnenforceable)?;
        let roots = self.roots.iter().collect::<Vec<_>>();
        let prepared = PreparedComposite::admit(&roots)
            .map_err(|_| NativeAdmissionError::EnforcementUnavailable)?;
        if matches!(
            scope.containment,
            ContainmentStrategy::SameUserCompositeV1 | ContainmentStrategy::SameUserCompositeV2
        ) {
            PreparedComposite::preflight_namespaces()
                .map_err(|_| NativeAdmissionError::EnforcementUnavailable)?;
        }
        if scope.containment == ContainmentStrategy::SameUserCompositeV2 {
            let fs = super::super::policy::native_fs_profile(&scope.filesystem.permissions)
                .map_err(|_| NativeAdmissionError::CompositePolicyUnenforceable)?;
            super::super::policy::preflight_composite_ruleset(fs)
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
                kind: PendingAdmissionKind::Generic,
            },
        );
        Ok(handle)
    }
}
