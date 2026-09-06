use runne_api::{QualificationFaultRelayBindingV1, QualificationFaultRelayDirectionV1};
use runne_native_qualification::{PendingQualificationFault, QualificationFaultRelayCodecV1};

use super::{
    BundledRuntimeLifecycleState, NativeProtectedCredentialEnrollmentBegin,
    PreparedProtectedCredentialEnrollment, ProtectedBundledRuntimeError,
    ProtectedBundledRuntimeProcess, ProtectedBundledRuntimeSupervisor, read_frame, write_frame,
};

impl ProtectedBundledRuntimeSupervisor {
    /// Begins the exact native enrollment path, consuming at most one
    /// qualification carrier on the current protected session.
    ///
    /// # Errors
    ///
    /// A present carrier is rejected after authenticated delivery until the
    /// independent runner-context admission slice exists.
    pub fn begin_protected_credential_enrollment_with_qualification(
        &mut self,
        request: NativeProtectedCredentialEnrollmentBegin,
        qualification_fault: Option<PendingQualificationFault>,
    ) -> Result<PreparedProtectedCredentialEnrollment, ProtectedBundledRuntimeError> {
        if self.state != BundledRuntimeLifecycleState::Ready || self.pending_profile.is_some() {
            return Err(ProtectedBundledRuntimeError::InvalidState);
        }
        self.process
            .as_mut()
            .ok_or(ProtectedBundledRuntimeError::OwnershipMismatch)?
            .begin_protected_credential_enrollment_with_qualification(request, qualification_fault)
    }
}

impl ProtectedBundledRuntimeProcess {
    pub(super) fn begin_protected_credential_enrollment_with_qualification(
        &mut self,
        request: NativeProtectedCredentialEnrollmentBegin,
        qualification_fault: Option<PendingQualificationFault>,
    ) -> Result<PreparedProtectedCredentialEnrollment, ProtectedBundledRuntimeError> {
        let Some(qualification_fault) = qualification_fault else {
            return self.begin_protected_credential_enrollment(request);
        };
        let (owned, _) = self.v3_enrollment_facts()?;
        let binding = QualificationFaultRelayBindingV1::new(
            *owned.session_id(),
            *owned.enrollment_binding().release_tuple_digest(),
            owned.launch_generation(),
            QualificationFaultRelayDirectionV1::DesktopToRuntime,
            1,
        )
        .map_err(ProtectedBundledRuntimeError::from)?;
        if write_initial_qualification_relay(
            &mut self.channel,
            &self.keys,
            binding,
            Some(qualification_fault),
        )? {
            let _closed = read_frame(&mut self.channel)?;
            return Err(ProtectedBundledRuntimeError::OwnershipMismatch);
        }
        self.begin_protected_credential_enrollment(request)
    }
}

pub(super) fn write_initial_qualification_relay(
    channel: &mut std::os::unix::net::UnixStream,
    keys: &runne_api::ProtectedActivationKeys,
    binding: QualificationFaultRelayBindingV1,
    pending: Option<PendingQualificationFault>,
) -> Result<bool, ProtectedBundledRuntimeError> {
    let Some(pending) = pending else {
        return Ok(false);
    };
    let codec = QualificationFaultRelayCodecV1::from_protected_activation(keys);
    let payload = pending
        .encode_relay(&codec, &binding)
        .map_err(|_| ProtectedBundledRuntimeError::InvalidState)?;
    let length =
        u32::try_from(payload.len()).map_err(|_| ProtectedBundledRuntimeError::InvalidState)?;
    let mut frame = Vec::with_capacity(payload.len() + 4);
    frame.extend_from_slice(&length.to_be_bytes());
    frame.extend_from_slice(&payload);
    write_frame(channel, &frame)?;
    Ok(true)
}
