impl ProtectedProcessActivation {
    const fn native_confirmation(
        &self,
        before: [u8; 32],
        after: [u8; 32],
    ) -> Result<NativeEnrollmentConfirmationV1, ProtectedBundledRuntimeError> {
        let (launch_authority, desktop_host, session, daemon, generation) = match self {
            Self::V2 { owned, .. } => {
                let owned = owned.compatibility_owned_launch();
                (*owned.launch_authority_id(), *owned.desktop_host_instance_id(),
                    *owned.session_id(), *owned.daemon_instance_id(), owned.launch_generation())
            }
            Self::V3 { owned, .. } => (
                *owned.launch_authority_id(), *owned.desktop_host_instance_id(),
                *owned.session_id(), *owned.daemon_instance_id(), owned.launch_generation(),
            ),
            _ => return Err(ProtectedBundledRuntimeError::InvalidState),
        };
        Ok(NativeEnrollmentConfirmationV1 {
            process_start_before: before, process_start_after: after,
            launch_authority, desktop_host, session, daemon, generation,
        })
    }
}
