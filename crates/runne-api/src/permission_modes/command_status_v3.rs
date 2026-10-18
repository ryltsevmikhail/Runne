use runne_domain::id::CommandId;
use serde::{Deserialize, Serialize};

use super::{PermissionModeChangeReceiptV1, PermissionModeChangeReceiptV2};

/// Version-discriminated receipt carried by the V3 readback contract.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "version", deny_unknown_fields)]
pub enum PermissionModeChangeReceiptV3 {
    #[serde(rename = "v1")]
    V1 {
        receipt: PermissionModeChangeReceiptV1,
    },
    #[serde(rename = "v2")]
    V2 {
        receipt: PermissionModeChangeReceiptV2,
    },
}

/// Safe V3 command readback. Pending states contain no proof or confirmation authority.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(
    tag = "state",
    rename_all = "camelCase",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum PermissionModeCommandStatusV3 {
    PendingNativeConfirmation {
        command_id: CommandId,
        expires_at_unix_ms: i64,
    },
    PendingReauthentication {
        command_id: CommandId,
        expires_at_unix_ms: i64,
    },
    Committed {
        receipt: Box<PermissionModeChangeReceiptV3>,
    },
    Cancelled {
        command_id: CommandId,
    },
    Expired {
        command_id: CommandId,
    },
    Invalidated {
        command_id: CommandId,
    },
}
