use crate::canonical::CanonicalId;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProjectTrustControlSnapshotDto {
    pub(super) project_id: CanonicalId,
    pub(super) project_name: String,
    pub(super) project_version: u64,
    pub(super) workspace_id: CanonicalId,
    pub(super) workspace_name: String,
    pub(super) workspace_version: u64,
    pub(super) status: ProjectTrustStatusDto,
    pub(super) managed_deny_mask: u32,
    pub(super) provenance: String,
    pub(super) epoch: u64,
    pub(super) revision: u64,
    pub(super) root_admission_version: Option<u64>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProjectTrustStatusDto {
    Untrusted,
    Trusted,
    Managed,
}

impl ProjectTrustControlSnapshotDto {
    pub const fn project_id(&self) -> CanonicalId {
        self.project_id
    }
    pub fn project_name(&self) -> &str {
        &self.project_name
    }
    pub const fn project_version(&self) -> u64 {
        self.project_version
    }
    pub const fn workspace_id(&self) -> CanonicalId {
        self.workspace_id
    }
    pub fn workspace_name(&self) -> &str {
        &self.workspace_name
    }
    pub const fn workspace_version(&self) -> u64 {
        self.workspace_version
    }
    pub const fn status(&self) -> ProjectTrustStatusDto {
        self.status
    }
    pub const fn managed_deny_mask(&self) -> u32 {
        self.managed_deny_mask
    }
    pub fn provenance(&self) -> &str {
        &self.provenance
    }
    pub const fn epoch(&self) -> u64 {
        self.epoch
    }
    pub const fn revision(&self) -> u64 {
        self.revision
    }
    pub const fn root_admission_version(&self) -> Option<u64> {
        self.root_admission_version
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProjectTrustDecisionDto {
    ConfirmProject,
    RevokeProject,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProjectTrustControlRequestDto {
    pub project_id: CanonicalId,
    pub workspace_id: CanonicalId,
    pub decision: ProjectTrustDecisionDto,
    pub expected_epoch: u64,
    pub expected_revision: u64,
    pub expected_project_version: u64,
    pub expected_workspace_version: u64,
    pub expected_root_admission_version: Option<u64>,
}
