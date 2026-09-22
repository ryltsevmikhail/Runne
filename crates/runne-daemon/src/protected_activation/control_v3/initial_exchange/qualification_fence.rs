use super::VerifiedQualificationAdmission;
use crate::application::provider_credential_enrollment::PostcommitAdmissionPermit;
use crate::application::provider_credential_enrollment::broker::{
    FencedWriterExchange, QualifiedIssuedTicket,
};
use crate::protected_activation::control_v3::qualification_admission::WriterAdmissionBundle;
use runne_api::{
    ProtectedCredentialEnrollmentOwnedLaunchV3, ProviderCredentialEnrollmentHostError as Error,
};
use sha2::{Digest as _, Sha256};

const HEADER_BYTES: usize = 17;

/// Exact authenticated members retained until the durable qualification fence commits.
pub(crate) struct QualificationAdmissionMembers {
    context: Vec<u8>,
    fault: Vec<u8>,
}

/// Consuming postcommit authority for the sole Writer admission encoding.
pub(crate) struct PostcommitQualificationAdmission {
    _admission: runne_native_qualification::PendingQualificationAdmission,
    permit: PostcommitAdmissionPermit,
    members: QualificationAdmissionMembers,
    qualified: QualifiedIssuedTicket,
}

impl VerifiedQualificationAdmission {
    pub(crate) fn retained_owned(&self) -> &ProtectedCredentialEnrollmentOwnedLaunchV3 {
        &self.owned
    }

    pub(crate) fn into_postcommit(
        self,
        qualified: QualifiedIssuedTicket,
        permit: PostcommitAdmissionPermit,
    ) -> PostcommitQualificationAdmission {
        PostcommitQualificationAdmission::new(self._admission, self.members, qualified, permit)
    }

    pub(crate) fn reverify_for_fence(
        &self,
        installed: &runne_platform_desktop::VerifiedInstalledEnrollmentMeasurementFacts,
        current: &ProtectedCredentialEnrollmentOwnedLaunchV3,
        verifier: &mut runne_native_qualification::QualificationAdmissionVerifier,
        now_unix_seconds: u64,
    ) -> Result<runne_native_qualification::VerifiedQualificationFenceFacts, Error> {
        if *self.owned != *current {
            return Err(Error::AccessDenied);
        }
        installed
            .verify_qualification_for_fence(current, verifier, &self._admission, now_unix_seconds)
            .map_err(|_| Error::AccessDenied)
    }
}

impl QualificationAdmissionMembers {
    pub(crate) fn from_relay_frames(context: &[u8], fault: &[u8]) -> Result<Self, Error> {
        Ok(Self {
            context: member(
                context,
                82,
                runne_native_qualification::MAX_RUN_CONTEXT_BYTES,
            )?,
            fault: member(
                fault,
                83,
                runne_native_qualification::MAX_FAULT_TICKET_BYTES,
            )?,
        })
    }

    #[cfg(test)]
    pub(crate) fn from_test_bundle(bytes: &[u8]) -> Result<Self, Error> {
        let context_len = length(bytes, 9)?;
        let ticket_len = length(bytes, 13)?;
        let context_end = HEADER_BYTES
            .checked_add(context_len)
            .ok_or(Error::AccessDenied)?;
        let ticket_end = context_end
            .checked_add(ticket_len)
            .ok_or(Error::AccessDenied)?;
        if bytes.get(..9) != Some(b"RNQADM1\0\x01") || ticket_end != bytes.len() {
            return Err(Error::AccessDenied);
        }
        Ok(Self {
            context: bytes
                .get(HEADER_BYTES..context_end)
                .ok_or(Error::AccessDenied)?
                .to_vec(),
            fault: bytes
                .get(context_end..ticket_end)
                .ok_or(Error::AccessDenied)?
                .to_vec(),
        })
    }
}

impl PostcommitQualificationAdmission {
    const fn new(
        admission: runne_native_qualification::PendingQualificationAdmission,
        members: QualificationAdmissionMembers,
        qualified: QualifiedIssuedTicket,
        permit: PostcommitAdmissionPermit,
    ) -> Self {
        Self {
            _admission: admission,
            permit,
            members,
            qualified,
        }
    }

    pub(crate) fn into_writer_exchange(self) -> Result<FencedWriterExchange, Error> {
        let context_len =
            u32::try_from(self.members.context.len()).map_err(|_| Error::AccessDenied)?;
        let ticket_len =
            u32::try_from(self.members.fault.len()).map_err(|_| Error::AccessDenied)?;
        let mut bytes = Vec::with_capacity(
            HEADER_BYTES + self.members.context.len() + self.members.fault.len(),
        );
        bytes.extend_from_slice(b"RNQADM1\0");
        bytes.push(1);
        bytes.extend_from_slice(&context_len.to_be_bytes());
        bytes.extend_from_slice(&ticket_len.to_be_bytes());
        bytes.extend_from_slice(&self.members.context);
        bytes.extend_from_slice(&self.members.fault);
        Ok(FencedWriterExchange::from_postcommit(
            self.qualified,
            WriterAdmissionBundle::from_signed_members(
                self.permit,
                bytes,
                Sha256::digest(&self.members.context).into(),
                Sha256::digest(&self.members.fault).into(),
            ),
        ))
    }
}

fn member(frame: &[u8], offset: usize, max: usize) -> Result<Vec<u8>, Error> {
    let length: [u8; 4] = frame
        .get(offset - 4..offset)
        .ok_or(Error::AccessDenied)?
        .try_into()
        .map_err(|_| Error::AccessDenied)?;
    let length = usize::try_from(u32::from_be_bytes(length)).map_err(|_| Error::AccessDenied)?;
    let end = offset.checked_add(length).ok_or(Error::AccessDenied)?;
    if !(1..=max).contains(&length) || frame.len() != end + 32 {
        return Err(Error::AccessDenied);
    }
    frame
        .get(offset..end)
        .map(ToOwned::to_owned)
        .ok_or(Error::AccessDenied)
}

#[cfg(test)]
fn length(bytes: &[u8], offset: usize) -> Result<usize, Error> {
    let bytes: [u8; 4] = bytes
        .get(offset..offset + 4)
        .ok_or(Error::AccessDenied)?
        .try_into()
        .map_err(|_| Error::AccessDenied)?;
    usize::try_from(u32::from_be_bytes(bytes)).map_err(|_| Error::AccessDenied)
}
