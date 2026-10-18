use runne_domain::id::CommandId;

/// MAC-verified address only; it is not transport authentication or consent.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PermissionControlRoutingHintV1 {
    pub(super) command_id: CommandId,
}

impl PermissionControlRoutingHintV1 {
    pub const fn command_id(self) -> CommandId {
        self.command_id
    }
}
