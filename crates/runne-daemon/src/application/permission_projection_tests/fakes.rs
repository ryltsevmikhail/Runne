use super::*;

pub(super) struct CountingAdmission {
    pub(super) readiness: AtomicUsize,
    pub(super) invocation: AtomicUsize,
}

impl CountingAdmission {
    pub(super) fn new() -> Self {
        Self {
            readiness: AtomicUsize::new(0),
            invocation: AtomicUsize::new(0),
        }
    }
}

impl NativeScopeAdmissionPort for CountingAdmission {
    fn admit_mode_readiness(
        &self,
        _mode: PermissionMode,
        _scope: &CompositeEffectScope,
    ) -> Result<IntegrityDigest, NativeAdmissionError> {
        self.readiness.fetch_add(1, Ordering::SeqCst);
        Ok(digest(41))
    }

    fn admit_scope(
        &self,
        _scope: &CompositeEffectScope,
    ) -> Result<IntegrityDigest, NativeAdmissionError> {
        self.invocation.fetch_add(1, Ordering::SeqCst);
        Ok(digest(42))
    }
}

pub(super) struct UnavailableAdmission(pub(super) AtomicUsize);

impl NativeScopeAdmissionPort for UnavailableAdmission {
    fn admit_mode_readiness(
        &self,
        _mode: PermissionMode,
        _scope: &CompositeEffectScope,
    ) -> Result<IntegrityDigest, NativeAdmissionError> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Err(NativeAdmissionError::EnforcementUnavailable)
    }

    fn admit_scope(
        &self,
        _scope: &CompositeEffectScope,
    ) -> Result<IntegrityDigest, NativeAdmissionError> {
        panic!("current projection must not admit an invocation")
    }
}

pub(super) fn digest(byte: u8) -> IntegrityDigest {
    IntegrityDigest::from_bytes([byte; 32])
}

pub(super) fn workspace(byte: u8) -> WorkspaceId {
    WorkspaceId::from_bytes([byte; 16])
}

pub(super) fn permission_scope(workspace_id: WorkspaceId) -> PermissionScope {
    PermissionScope {
        runtime_authority_id: RuntimeAuthorityId("runtime-projection-test".into()),
        principal_id: ApiPrincipalId::new("user:projection-test").unwrap(),
        workspace_id,
    }
}

pub(super) fn selection(mode: PermissionMode, revision: u64, expiry: Option<i64>) -> ModeSelection {
    ModeSelection {
        scope: permission_scope(workspace(3)),
        selected_mode: mode,
        preset_version: PresetVersion::V1,
        authorization_revision: revision,
        expires_at_unix_ms: expiry,
    }
}

pub(super) fn trust_snapshot(revision: u64) -> ProjectTrustEffectPolicySnapshot {
    ProjectTrustEffectPolicySnapshot {
        record: ProjectTrustRecord {
            status: ProjectTrustStatus::Trusted,
            instance_epoch: 7,
            revision,
            managed_deny_mask: 0,
        },
        policy: ManagedEffectPolicyV1::all_allow(),
    }
}

#[cfg(target_os = "linux")]
pub(super) fn managed_identity(
    selection: ModeSelection,
    revision: u64,
    policy_digest: IntegrityDigest,
) -> PermissionModeSelectionManagedIdentity {
    PermissionModeSelectionManagedIdentity {
        selection,
        identity: ManagedIdentityMetadata::ClosedRulesV2(ClosedRulesManagedIdentityV2 {
            project_id: [9; 16],
            project_version: 2,
            snapshot: trust_snapshot(revision),
            canonical_digest: policy_digest,
            challenge_binding: None,
        }),
    }
}
