use super::super::{
    LinuxCommandError, LinuxCompositeScopeAdmission, snapshot::SealedExecutableSnapshot,
};
use super::codec;
use runne_domain::task_run::TaskRunLocalCommand;
use std::fs::File;
use std::sync::Arc;

/// Registered native owner allocated once from the protected-root admission owner.
pub struct LinuxPermissionOwnerV1 {
    pub(super) owner_id: [u8; 16],
    pub(super) generation: u64,
    pub(super) admission: Arc<LinuxCompositeScopeAdmission>,
}

/// Restricted target-preparation view paired with one native owner.
#[derive(Clone)]
pub struct LinuxPermissionPreparationV1 {
    owner_id: [u8; 16],
    generation: u64,
    pub(super) admission: Arc<LinuxCompositeScopeAdmission>,
}

/// Read-only target observations; these fields alone cannot spawn or release a child.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PermissionTargetObservationV1 {
    pub(super) owner_id: [u8; 16],
    pub(super) owner_generation: u64,
    pub(super) target_identity: [u8; 32],
    pub(super) target_version: u64,
    pub(super) workspace_identity: [u8; 32],
    pub(super) cwd_identity: [u8; 32],
    pub(super) executable_digest: [u8; 32],
    pub(super) environment_digest: [u8; 32],
    pub(super) normalized_arguments_digest: [u8; 32],
    pub(super) schema_digest: [u8; 32],
}

impl LinuxPermissionOwnerV1 {
    /// Creates a fresh owner/preparation pair around the actual held protected-root registry.
    pub fn new(
        admission: Arc<LinuxCompositeScopeAdmission>,
    ) -> Result<Arc<Self>, LinuxCommandError> {
        let (owner_id, generation) = admission.permission_lineage();
        Ok(Arc::new(Self {
            owner_id,
            generation,
            admission,
        }))
    }

    /// Returns a preparation-only view. It has no release method or child token.
    pub fn preparation(self: &Arc<Self>) -> LinuxPermissionPreparationV1 {
        LinuxPermissionPreparationV1 {
            owner_id: self.owner_id,
            generation: self.generation,
            admission: Arc::clone(&self.admission),
        }
    }
}

impl LinuxPermissionPreparationV1 {
    pub(super) const fn permission_lineage(&self) -> ([u8; 16], u64) {
        (self.owner_id, self.generation)
    }

    /// Prepares exactly the structured command and held descriptors supplied by the broker.
    pub fn prepare_target(
        &self,
        command: TaskRunLocalCommand,
        workspace: &File,
        cwd: &File,
        snapshot: SealedExecutableSnapshot,
    ) -> Result<super::bound_spec::PreparedPermissionTargetV1, LinuxCommandError> {
        if self.generation == 0 {
            return Err(LinuxCommandError::Unverified);
        }
        let workspace = workspace
            .try_clone()
            .map_err(|_| LinuxCommandError::Unavailable)?;
        let cwd = cwd
            .try_clone()
            .map_err(|_| LinuxCommandError::Unavailable)?;
        let (target_identity, workspace_identity, cwd_identity, executable_digest) =
            codec::target_digest(&snapshot, &workspace, &cwd)?;
        let environment_digest = codec::environment_digest(&command)?;
        let observation = PermissionTargetObservationV1 {
            owner_id: self.owner_id,
            owner_generation: self.generation,
            target_identity,
            target_version: snapshot.permission_identity().1,
            workspace_identity,
            cwd_identity,
            executable_digest,
            environment_digest,
            normalized_arguments_digest: command.intent_digest(),
            schema_digest: codec::schema_digest(),
        };
        Ok(super::bound_spec::PreparedPermissionTargetV1 {
            command,
            workspace,
            cwd,
            snapshot,
            observation,
            admission: Arc::clone(&self.admission),
        })
    }
}

impl PermissionTargetObservationV1 {
    /// Returns the digest of the retained executable target identity.
    pub const fn target_identity(&self) -> &[u8; 32] {
        &self.target_identity
    }

    /// Returns the sealed target generation used in that identity.
    pub const fn target_version(&self) -> u64 {
        self.target_version
    }

    /// Returns the registered native owner identifier as data only.
    pub const fn owner_id(&self) -> &[u8; 16] {
        &self.owner_id
    }

    /// Returns the registered native owner generation as data only.
    pub const fn owner_generation(&self) -> u64 {
        self.owner_generation
    }

    /// Returns the held workspace descriptor identity digest.
    pub const fn workspace_identity(&self) -> &[u8; 32] {
        &self.workspace_identity
    }

    /// Returns the held working-directory descriptor identity digest.
    pub const fn cwd_identity(&self) -> &[u8; 32] {
        &self.cwd_identity
    }

    /// Returns the sealed executable bytes digest.
    pub const fn executable_digest(&self) -> &[u8; 32] {
        &self.executable_digest
    }

    /// Returns the normalized command environment digest.
    pub const fn environment_digest(&self) -> &[u8; 32] {
        &self.environment_digest
    }

    /// Returns the normalized structured-arguments digest.
    pub const fn normalized_arguments_digest(&self) -> &[u8; 32] {
        &self.normalized_arguments_digest
    }

    /// Returns the closed command schema digest.
    pub const fn schema_digest(&self) -> &[u8; 32] {
        &self.schema_digest
    }
}
