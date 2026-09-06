use std::io::Write as _;

use runne_api::{
    QualificationFaultRelayBindingV1, QualificationFaultRelayDirectionV1,
    QualificationRunContextRelayBindingV1, QualificationRunContextRelayDirectionV1,
};
use runne_native_qualification::{
    PendingQualificationAdmission, QualificationAdmissionRelayCodecV1,
};

use super::{
    BundledRuntimeLifecycleState, NativeProtectedCredentialEnrollmentBegin,
    PreparedProtectedCredentialEnrollment, ProtectedBundledRuntimeError,
    ProtectedBundledRuntimeProcess, ProtectedBundledRuntimeSupervisor, read_frame,
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
        qualification_admission: Option<PendingQualificationAdmission>,
    ) -> Result<PreparedProtectedCredentialEnrollment, ProtectedBundledRuntimeError> {
        if self.state != BundledRuntimeLifecycleState::Ready || self.pending_profile.is_some() {
            return Err(ProtectedBundledRuntimeError::InvalidState);
        }
        self.process
            .as_mut()
            .ok_or(ProtectedBundledRuntimeError::OwnershipMismatch)?
            .begin_protected_credential_enrollment_with_qualification(
                request,
                qualification_admission,
            )
    }
}

impl ProtectedBundledRuntimeProcess {
    pub(super) fn begin_protected_credential_enrollment_with_qualification(
        &mut self,
        request: NativeProtectedCredentialEnrollmentBegin,
        qualification_admission: Option<PendingQualificationAdmission>,
    ) -> Result<PreparedProtectedCredentialEnrollment, ProtectedBundledRuntimeError> {
        let Some(qualification_admission) = qualification_admission else {
            return self.begin_protected_credential_enrollment(request);
        };
        let (owned, _) = self.v3_enrollment_facts()?;
        let context_binding = QualificationRunContextRelayBindingV1::new(
            *owned.session_id(),
            *owned.enrollment_binding().release_tuple_digest(),
            owned.launch_generation(),
            QualificationRunContextRelayDirectionV1::DesktopToRuntime,
            1,
        )
        .map_err(ProtectedBundledRuntimeError::from)?;
        let fault_binding = QualificationFaultRelayBindingV1::new(
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
            context_binding,
            fault_binding,
            Some(qualification_admission),
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
    context_binding: QualificationRunContextRelayBindingV1,
    fault_binding: QualificationFaultRelayBindingV1,
    pending: Option<PendingQualificationAdmission>,
) -> Result<bool, ProtectedBundledRuntimeError> {
    let Some(pending) = pending else {
        return Ok(false);
    };
    let codec = QualificationAdmissionRelayCodecV1::from_protected_activation(keys);
    let transcript = pending
        .encode_relay_transcript(&codec, &context_binding, &fault_binding)
        .map_err(|_| ProtectedBundledRuntimeError::InvalidState)?;
    channel
        .write_all(&transcript.into_bytes())
        .and_then(|()| channel.flush())
        .map_err(|_| ProtectedBundledRuntimeError::ProtectedChannelUnavailable)?;
    Ok(true)
}
