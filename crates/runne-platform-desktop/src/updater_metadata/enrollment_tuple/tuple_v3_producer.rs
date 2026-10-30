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

#[path = "tuple_v3_producer/qualification_receipt.rs"]
mod qualification_receipt;

use layout::{MeasuredTupleV3Artifacts, StagedTupleV3Artifacts};
use resources::ValidatedTupleV3Resources;

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

/// Builds the tuple with a local macOS qualification row.
///
/// The receipt must bind this commit, artifact, and every measured input; a
/// stale, expired, reused, or mismatched receipt is rejected.
#[cfg(target_os = "macos")]
pub fn produce_staged_native_enrollment_tuple_v3_qualified(
    candidate_app: &Path,
    target: &UpdateTargetV2,
    receipt: &Path,
    qualified_at: u64,
    qualification_expires: u64,
) -> Result<NativeEnrollmentTupleV3, NativeEnrollmentTupleError> {
    produce_qualified_with_observer(
        candidate_app,
        target,
        receipt,
        qualified_at,
        qualification_expires,
        &identity::NativeCodeIdentityObserver,
    )
}

pub(super) fn produce_with_observer(
    candidate_app: &Path,
    target: &UpdateTargetV2,
    observer: &impl CodeIdentityObserver,
) -> Result<NativeEnrollmentTupleV3, NativeEnrollmentTupleError> {
    let (tuple, _) = assemble(candidate_app, target, observer)?;
    Ok(tuple)
}

pub(super) fn produce_qualified_with_observer(
    candidate_app: &Path,
    target: &UpdateTargetV2,
    receipt: &Path,
    qualified_at: u64,
    qualification_expires: u64,
    observer: &impl CodeIdentityObserver,
) -> Result<NativeEnrollmentTupleV3, NativeEnrollmentTupleError> {
    let (tuple, measurement) = assemble(candidate_app, target, observer)?;
    let bytes = std::fs::read(receipt).map_err(|_| NativeEnrollmentTupleError::Rejected)?;
    let receipt_sha256 = qualification_receipt::verify(
        &bytes,
        target,
        &measurement.resources,
        &measurement.measured,
        qualified_at,
        qualification_expires,
    )?;
    let row = runne_api::NativeEnrollmentQualificationRowV1::new_v3(
        target,
        &tuple,
        receipt_sha256,
        qualified_at,
        qualification_expires,
    )?;
    tuple.with_qualification(target, row)
}

struct TupleMeasurement {
    resources: ValidatedTupleV3Resources,
    measured: MeasuredTupleV3Artifacts,
}

fn assemble(
    candidate_app: &Path,
    target: &UpdateTargetV2,
    observer: &impl CodeIdentityObserver,
) -> Result<(NativeEnrollmentTupleV3, TupleMeasurement), NativeEnrollmentTupleError> {
    let artifacts = StagedTupleV3Artifacts::capture(candidate_app)?;
    observer.verify_bundle(artifacts.application_path())?;
    let resources = artifacts.validate_resources(target)?;
    let measured = artifacts.measure()?;
    let identities = artifacts.observe_identities(observer)?;
    artifacts.confirm_current()?;
    let tuple = NativeEnrollmentTupleV3::new(
        NativeEnrollmentTupleV3Digests {
            candidate_sha256: resources.release_candidate_sha256.clone(),
            desktop_sha256: measured.desktop.clone(),
            writer_sha256: measured.writer.clone(),
            daemon_sha256: measured.daemon.clone(),
            credential_service_sha256: measured.credential_service.clone(),
            launch_agent_plist_sha256: measured.launch_agent.clone(),
            entitlements_sha256: measured.entitlements.clone(),
            provisioning_sha256: measured.provisioning.clone(),
            xpc_protocol_sha256: measured.xpc_protocol.clone(),
            contract_sha256: measured.contract.clone(),
        },
        NativeEnrollmentTupleV3Deployment::exact(resources.protocol_versions.clone()),
        identities,
        target,
    )?;
    Ok((
        tuple,
        TupleMeasurement {
            resources,
            measured,
        },
    ))
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
