use super::*;

pub(super) struct PreparedLocalCommand {
    pub(super) files: runne_platform_desktop::LinuxCommandFiles,
    pub(super) executable: SealedExecutableSnapshot,
    pub(super) binding: LocalCommandApprovalBinding,
    pub(super) approval_digest: [u8; 32],
    pub(super) trust: TrustToken,
}

pub(super) enum LocalApprovalDecision {
    Pending,
    Approved,
    Rejected,
}
