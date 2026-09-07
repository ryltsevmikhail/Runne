use std::path::Path;

use core_foundation::url::CFURL;
use runne_api::VerifiedSignedNativeEnrollmentTupleV3;
use security_framework::os::macos::code_signing::{Flags, SecCode, SecStaticCode};

use super::{MatchedSignedCodeIdentity, NativeSignedCodeIdentity};
use crate::MacOsPackagedWriterObservationError;

#[derive(Clone, Copy)]
pub enum ServiceIdentityRole {
    Desktop,
    Writer,
    Daemon,
    CredentialService,
}

pub fn match_service_static_identities(
    tuple: &VerifiedSignedNativeEnrollmentTupleV3,
    paths: &[impl AsRef<Path>; 4],
) -> Result<(), MacOsPackagedWriterObservationError> {
    for (role, path) in [
        ServiceIdentityRole::Desktop,
        ServiceIdentityRole::Writer,
        ServiceIdentityRole::Daemon,
        ServiceIdentityRole::CredentialService,
    ]
    .into_iter()
    .zip(paths)
    {
        let path = path.as_ref();
        let url =
            CFURL::from_path(path, false).ok_or(MacOsPackagedWriterObservationError::Rejected)?;
        let code = SecStaticCode::from_path(&url, Flags::NONE)
            .map_err(|_| MacOsPackagedWriterObservationError::Rejected)?;
        crate::packaged_writer_observation::security_code::static_main_executable(&code)?
            .eq(path)
            .then_some(())
            .ok_or(MacOsPackagedWriterObservationError::Rejected)?;
        match_static(tuple, role, &code)?;
    }
    Ok(())
}

pub fn match_service_dynamic_identity(
    tuple: &VerifiedSignedNativeEnrollmentTupleV3,
    code: &SecCode,
) -> Result<(), MacOsPackagedWriterObservationError> {
    let observed = NativeSignedCodeIdentity::for_dynamic_code(code)?;
    let matched = match_v3_identity(tuple, ServiceIdentityRole::CredentialService, observed)?;
    matched.check_dynamic_code(code)
}

fn match_static(
    tuple: &VerifiedSignedNativeEnrollmentTupleV3,
    role: ServiceIdentityRole,
    code: &SecStaticCode,
) -> Result<(), MacOsPackagedWriterObservationError> {
    let observed = NativeSignedCodeIdentity::for_static_code(code)?;
    let matched = match_v3_identity(tuple, role, observed)?;
    matched.check_static_code(code)
}

fn match_v3_identity(
    tuple: &VerifiedSignedNativeEnrollmentTupleV3,
    role: ServiceIdentityRole,
    observed: NativeSignedCodeIdentity,
) -> Result<MatchedSignedCodeIdentity, MacOsPackagedWriterObservationError> {
    let cdhash = observed.cdhash_hex();
    let matches = match role {
        ServiceIdentityRole::Desktop => {
            tuple.matches_desktop_identity(&observed.identifier, &observed.team_identifier, &cdhash)
        }
        ServiceIdentityRole::Writer => {
            tuple.matches_writer_identity(&observed.identifier, &observed.team_identifier, &cdhash)
        }
        ServiceIdentityRole::Daemon => {
            tuple.matches_daemon_identity(&observed.identifier, &observed.team_identifier, &cdhash)
        }
        ServiceIdentityRole::CredentialService => tuple.matches_credential_service_identity(
            &observed.identifier,
            &observed.team_identifier,
            &cdhash,
        ),
    };
    matches
        .then_some(MatchedSignedCodeIdentity { observed })
        .ok_or(MacOsPackagedWriterObservationError::Rejected)
}
