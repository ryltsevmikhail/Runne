use runne_domain::id::CommandId;
use serde::{Deserialize, Serialize};

use super::PermissionModeChangeReceiptV1;

/// Safe readback state for a permission-mode command.
///
/// Pending states are reported only after their canonical command has been
/// stored. This DTO carries no proof, nonce, principal, origin, or confirmation
/// authority.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(
    tag = "state",
    rename_all = "snake_case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum PermissionModeCommandStatusV2 {
    PendingNativeConfirmation {
        command_id: CommandId,
        expires_at_unix_ms: i64,
    },
    PendingReauthentication {
        command_id: CommandId,
        expires_at_unix_ms: i64,
    },
    Committed {
        receipt: PermissionModeChangeReceiptV1,
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
