use serde::{Deserialize, Serialize};

use super::PermissionNetworkStateV2;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum PermissionFilesystemPostureV2 {
    None,
    BoundedRoots,
    BroadSameUser,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum PermissionFilesystemRightV2 {
    Read,
    Create,
    Write,
    Delete,
}

impl PermissionFilesystemRightV2 {
    pub(crate) const fn order(self) -> u8 {
        match self {
            Self::Read => 0,
            Self::Create => 1,
            Self::Write => 2,
            Self::Delete => 3,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PermissionFilesystemScopeV2 {
    pub posture: PermissionFilesystemPostureV2,
    pub rights: Vec<PermissionFilesystemRightV2>,
}

impl PermissionFilesystemScopeV2 {
    #[must_use]
    pub fn has_right(&self, right: PermissionFilesystemRightV2) -> bool {
        self.rights.contains(&right)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum PermissionProcessScopeV2 {
    None,
    ArbitraryInsideContainment,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum PermissionSourceIngressDeniedReasonV2 {
    ManagedDeny,
    SourcePolicyDenied,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum PermissionSourceIngressUnavailableReasonV2 {
    ProvenanceUnavailable,
    CurrentEvidenceUnavailable,
    Unsupported,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(
    tag = "state",
    rename_all = "camelCase",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum PermissionSourceIngressV2 {
    Available,
    Denied {
        reason: PermissionSourceIngressDeniedReasonV2,
    },
    Unavailable {
        reason: PermissionSourceIngressUnavailableReasonV2,
    },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PermissionModeScopesV2 {
    pub filesystem: PermissionFilesystemScopeV2,
    pub process: PermissionProcessScopeV2,
    pub network: PermissionNetworkStateV2,
    pub source_ingress: PermissionSourceIngressV2,
}

impl PermissionModeScopesV2 {
    pub(crate) fn filesystem_right_for(
        action: super::PermissionActionV2,
    ) -> Option<PermissionFilesystemRightV2> {
        match action {
            super::PermissionActionV2::FsRead => Some(PermissionFilesystemRightV2::Read),
            super::PermissionActionV2::FsCreate => Some(PermissionFilesystemRightV2::Create),
            super::PermissionActionV2::FsWrite => Some(PermissionFilesystemRightV2::Write),
            super::PermissionActionV2::FsDelete => Some(PermissionFilesystemRightV2::Delete),
            super::PermissionActionV2::ProcessStart | super::PermissionActionV2::NetworkUse => None,
        }
    }
}
