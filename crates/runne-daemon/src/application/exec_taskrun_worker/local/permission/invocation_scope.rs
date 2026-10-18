use runne_application::permission_modes::{CompositeEffectScope, ModeSelection, PermissionScope};
use runne_application::project_trust::{ProjectTrustEffectPolicySnapshot, ProjectTrustProjectId};
use runne_runtime::taskrun_auto_worker::AutomaticTaskRunError;

pub(super) fn invocation_scope(
    selection: &ModeSelection,
    permission_scope: PermissionScope,
    project: ProjectTrustProjectId,
    trust: &ProjectTrustEffectPolicySnapshot,
    native: &runne_platform::local_command_linux::LinuxCompositeScopeAdmission,
) -> Result<CompositeEffectScope, AutomaticTaskRunError> {
    let network = if selection.selected_mode
        == runne_application::permission_modes::PermissionMode::FullAccess
    {
        runne_application::permission_modes::NetworkScope::BroadSameUser
    } else {
        runne_application::permission_modes::NetworkScope::None
    };
    let protected_digest = native
        .protected_control_plane_policy_digest_v2(network)
        .map_err(|_| AutomaticTaskRunError::RejectedBeforeEffect)?;
    crate::application::permission_projection::local_command_scope(
        selection,
        permission_scope,
        project,
        trust,
        protected_digest,
    )
    .map_err(|_| AutomaticTaskRunError::RejectedBeforeEffect)
}
