use super::{
    PermissionControlSequenceV1, ProtectedBundledRuntimeError, ProtectedProcessActivation,
};

pub(super) type PermissionControlOwnerV1 = ([u8; 16], [u8; 16], [u8; 16], u64, u64, [u8; 16]);
pub(super) type PermissionControlChannelOwnerV1 = ([u8; 16], [u8; 16], [u8; 16], u64, [u8; 16]);

pub(super) const fn permission_owner_identity(
    activation: &ProtectedProcessActivation,
) -> Result<
    (
        &runne_api::StableRuntimeBindingV1,
        PermissionControlChannelOwnerV1,
    ),
    ProtectedBundledRuntimeError,
> {
    let (stable, authority, desktop, daemon, generation, session) = match activation {
        ProtectedProcessActivation::V1 { owned, .. } => (
            owned.stable(),
            *owned.launch_authority_id(),
            *owned.desktop_host_instance_id(),
            *owned.daemon_instance_id(),
            owned.launch_generation(),
            *owned.session_id(),
        ),
        ProtectedProcessActivation::V2 { owned, .. } => {
            let base = owned.compatibility_owned_launch();
            (
                base.stable(),
                *base.launch_authority_id(),
                *base.desktop_host_instance_id(),
                *base.daemon_instance_id(),
                base.launch_generation(),
                *base.session_id(),
            )
        }
        ProtectedProcessActivation::V3 { owned, .. } => (
            owned.stable(),
            *owned.launch_authority_id(),
            *owned.desktop_host_instance_id(),
            *owned.daemon_instance_id(),
            owned.launch_generation(),
            *owned.session_id(),
        ),
        #[cfg(feature = "test-support")]
        _ => return Err(ProtectedBundledRuntimeError::InvalidState),
    };
    Ok((stable, (authority, desktop, daemon, generation, session)))
}

pub(super) fn same_permission_channel(
    left: &PermissionControlOwnerV1,
    right: &PermissionControlOwnerV1,
) -> bool {
    left.0 == right.0 && left.1 == right.1 && left.2 == right.2
}

pub(super) fn rebind_permission_sequence(
    sequence: &mut PermissionControlSequenceV1,
    owner: PermissionControlOwnerV1,
) -> Result<(), ProtectedBundledRuntimeError> {
    if !same_permission_channel(&sequence.owner, &owner) {
        return Err(ProtectedBundledRuntimeError::OwnershipMismatch);
    }
    if sequence.owner != owner {
        let new_key_epoch = sequence.owner.4 != owner.4;
        sequence.owner = owner;
        sequence.active = None;
        if new_key_epoch {
            sequence.last_authenticated_sequence = 0;
        }
    }
    Ok(())
}
