use super::{
    LinuxCommandError, child::composite::PreparedComposite,
    permission::PermissionHelperOperationV1, snapshot::SealedExecutableSnapshot,
};
use runne_application::permission_modes::{
    CompositeEffectScope, CompositeScopeDigest, ContainmentStrategy, IntegrityDigest,
    NativeScopeAdmissionReceipt, NetworkScope,
};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs::File;
use std::sync::Mutex;
use std::time::Instant;
#[path = "composite_admission/helper.rs"]
mod helper;
#[path = "composite_admission/readiness.rs"]
mod readiness;
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
    kind: PendingAdmissionKind,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PendingAdmissionKind {
    Generic,
    HelperScope(PermissionHelperOperationV1),
    HelperRequest {
        operation: PermissionHelperOperationV1,
        request_digest: [u8; 32],
    },
}

/// Runtime-owned registry of held reserved-root descriptors and one-shot scope tokens.
pub struct LinuxCompositeScopeAdmission {
    roots: Vec<File>,
    permission_owner_id: [u8; 16],
    permission_generation: u64,
    protected_policy_digest: IntegrityDigest,
    protected_policy_digest_v2_broad: IntegrityDigest,
    protected_policy_digest_v2_none: IntegrityDigest,
    protected_policy_digest_v3_broad: IntegrityDigest,
    protected_policy_digest_v3_none: IntegrityDigest,
    pending: Mutex<HashMap<IntegrityDigest, PendingAdmission>>,
    helper_executable: Option<SealedExecutableSnapshot>,
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
        let protected_policy_digest_v2_broad = PreparedComposite::protected_policy_digest_v2(
            &references,
            NetworkScope::BroadSameUser,
        )?;
        let protected_policy_digest_v2_none =
            PreparedComposite::protected_policy_digest_v2(&references, NetworkScope::None)?;
        let protected_policy_digest_v3_broad = PreparedComposite::protected_policy_digest_v3(
            &references,
            NetworkScope::BroadSameUser,
        )?;
        let protected_policy_digest_v3_none =
            PreparedComposite::protected_policy_digest_v3(&references, NetworkScope::None)?;
        drop(prepared);
        let (permission_owner_id, permission_generation) = permission_lineage()?;
        let helper_executable = File::open("/proc/self/exe")
            .ok()
            .and_then(|image| SealedExecutableSnapshot::from_held_file(&image).ok());
        Ok(Self {
            roots,
            permission_owner_id,
            permission_generation,
            protected_policy_digest,
            protected_policy_digest_v2_broad,
            protected_policy_digest_v2_none,
            protected_policy_digest_v3_broad,
            protected_policy_digest_v3_none,
            pending: Mutex::new(HashMap::new()),
            helper_executable,
        })
    }

    /// Digest to place in `CompositeEffectScope` before asking this port to admit it.
    #[must_use]
    pub const fn protected_control_plane_policy_digest(&self) -> IntegrityDigest {
        self.protected_policy_digest
    }

    pub(super) const fn permission_lineage(&self) -> ([u8; 16], u64) {
        (self.permission_owner_id, self.permission_generation)
    }

    pub(super) fn inspect(
        &self,
        scope: &CompositeEffectScope,
        receipt: NativeScopeAdmissionReceipt,
        workspace: &File,
        cwd: &File,
        consume: bool,
    ) -> Result<(Option<PreparedComposite>, bool), LinuxCommandError> {
        let protected = self
            .protected_identity(scope)
            .ok_or(LinuxCommandError::CompositePolicyUnenforceable)?;
        validate_scope(scope, protected)
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
            || token.kind != PendingAdmissionKind::Generic
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
                if !matches!(
                    scope.containment,
                    ContainmentStrategy::SameUserCompositeV1
                        | ContainmentStrategy::SameUserCompositeV2
                ) {
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
}

fn permission_lineage() -> Result<([u8; 16], u64), LinuxCommandError> {
    let mut bytes = [0; 24];
    let mut filled = 0;
    while filled < bytes.len() {
        let result = unsafe {
            libc::getrandom(bytes[filled..].as_mut_ptr().cast(), bytes.len() - filled, 0)
        };
        if result < 0 && std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted {
            continue;
        }
        if result <= 0 {
            return Err(LinuxCommandError::Unavailable);
        }
        filled += result as usize;
    }
    let mut owner = [0; 16];
    owner.copy_from_slice(&bytes[..16]);
    let generation = u64::from_be_bytes(
        bytes[16..]
            .try_into()
            .map_err(|_| LinuxCommandError::Unavailable)?,
    );
    if owner == [0; 16] || generation == 0 {
        return Err(LinuxCommandError::Unavailable);
    }
    Ok((owner, generation))
}
