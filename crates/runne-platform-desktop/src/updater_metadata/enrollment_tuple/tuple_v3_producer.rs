//! Production of tuple V3 from retained staged-package artifacts.

use std::path::Path;

use runne_api::{
    MacOsCodeIdentityExpectationV1, NativeEnrollmentTupleError, NativeEnrollmentTupleV3,
    NativeEnrollmentTupleV3CodeIdentities, NativeEnrollmentTupleV3Deployment,
    NativeEnrollmentTupleV3Digests, UpdateTargetV2,
};

#[path = "tuple_v3_producer/identity.rs"]
mod identity;
#[path = "tuple_v3_producer/layout.rs"]
mod layout;
#[path = "tuple_v3_producer/resources.rs"]
mod resources;
#[cfg(test)]
#[path = "tuple_v3_producer/verification_tests.rs"]
mod verification_tests;

use layout::StagedTupleV3Artifacts;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum CodeIdentityRole {
    Desktop,
    Writer,
    Daemon,
    CredentialService,
}

pub(super) trait CodeIdentityObserver {
    fn verify_bundle(&self, path: &Path) -> Result<(), NativeEnrollmentTupleError>;

    fn observe(
        &self,
        role: CodeIdentityRole,
        path: &Path,
    ) -> Result<MacOsCodeIdentityExpectationV1, NativeEnrollmentTupleError>;
}

/// Builds the signed-metadata tuple from one exact staged `Runne.app`.
///
/// The caller supplies no artifact digests or code identities. All paths are
/// resolved descriptor-relatively below the app and identities are observed
/// from the signed code at those fixed paths.
#[cfg(target_os = "macos")]
pub fn produce_staged_native_enrollment_tuple_v3(
    candidate_app: &Path,
    target: &UpdateTargetV2,
) -> Result<NativeEnrollmentTupleV3, NativeEnrollmentTupleError> {
    produce_with_observer(candidate_app, target, &identity::NativeCodeIdentityObserver)
}

pub(super) fn produce_with_observer(
    candidate_app: &Path,
    target: &UpdateTargetV2,
    observer: &impl CodeIdentityObserver,
) -> Result<NativeEnrollmentTupleV3, NativeEnrollmentTupleError> {
    let artifacts = StagedTupleV3Artifacts::capture(candidate_app)?;
    observer.verify_bundle(artifacts.application_path())?;
    let resources = artifacts.validate_resources(target)?;
    let measured = artifacts.measure()?;
    let identities = artifacts.observe_identities(observer)?;
    artifacts.confirm_current()?;
    NativeEnrollmentTupleV3::new(
        NativeEnrollmentTupleV3Digests {
            candidate_sha256: resources.release_candidate_sha256,
            desktop_sha256: measured.desktop,
            writer_sha256: measured.writer,
            daemon_sha256: measured.daemon,
            credential_service_sha256: measured.credential_service,
            launch_agent_plist_sha256: measured.launch_agent,
            entitlements_sha256: measured.entitlements,
            provisioning_sha256: measured.provisioning,
            xpc_protocol_sha256: measured.xpc_protocol,
            contract_sha256: measured.contract,
        },
        NativeEnrollmentTupleV3Deployment::exact(resources.protocol_versions),
        identities,
        target,
    )
}

fn code_identities(
    observer: &impl CodeIdentityObserver,
    paths: [&Path; 4],
) -> Result<NativeEnrollmentTupleV3CodeIdentities, NativeEnrollmentTupleError> {
    Ok(NativeEnrollmentTupleV3CodeIdentities::new(
        observer.observe(CodeIdentityRole::Desktop, paths[0])?,
        observer.observe(CodeIdentityRole::Writer, paths[1])?,
        observer.observe(CodeIdentityRole::Daemon, paths[2])?,
        observer.observe(CodeIdentityRole::CredentialService, paths[3])?,
    ))
}
