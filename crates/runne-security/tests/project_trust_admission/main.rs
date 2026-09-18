//! T1 source-admission authority invariants (NM analogues at policy level):
//! untrusted default, activation gates, managed deny vs permission modes,
//! epoch-scoped tokens (F1), mandatory file-read paths (F3), fail-closed
//! authority, and stage-2 delegation.

use std::sync::Arc;

use runne_application::prohibited_content::{CanonicalContentBoundary, ContentDisposition};
use runne_application::project_trust::{
    PermissionMode, ProjectTrustRecord, ProjectTrustStatus, SourceChannel, SourceDenyReason,
    TrustAdmissionError, TrustToken,
};
use runne_security::project_trust_policy::ProjectTrustPolicyAuthority;

mod harness;
use harness::{
    EPOCH, FakePersistence, UnavailableInspection, WorkingInspection, project, request, trusted,
};

#[test]
fn untrusted_default_denies_every_channel() {
    let authority = ProjectTrustPolicyAuthority::new(Arc::new(FakePersistence::with(
        ProjectTrustRecord::untrusted_default(EPOCH),
    )));
    for channel in [
        SourceChannel::Instructions,
        SourceChannel::Skills,
        SourceChannel::Hooks,
        SourceChannel::Helpers,
        SourceChannel::McpLocal,
        SourceChannel::FilesList,
        SourceChannel::FilesRead,
    ] {
        let error = authority
            .admit_source(project(), request(channel, Some("src/main.rs")))
            .unwrap_err();
        assert_eq!(
            error,
            TrustAdmissionError::DeniedByPolicy {
                reason: SourceDenyReason::Untrusted
            },
            "channel {channel:?} must be denied while untrusted"
        );
    }
}

#[test]
fn activation_gated_channels_stay_unavailable_even_when_trusted() {
    let authority = ProjectTrustPolicyAuthority::new(Arc::new(FakePersistence::with(trusted(3))));
    for channel in [
        SourceChannel::Instructions,
        SourceChannel::Skills,
        SourceChannel::Hooks,
        SourceChannel::Helpers,
        SourceChannel::McpLocal,
    ] {
        let error = authority
            .admit_source(project(), request(channel, Some("AGENTS.md")))
            .unwrap_err();
        assert_eq!(
            error,
            TrustAdmissionError::DeniedByPolicy {
                reason: SourceDenyReason::ChannelUnavailable
            },
            "channel {channel:?} has no activation gate"
        );
    }
    authority
        .admit_source(
            project(),
            request(SourceChannel::FilesRead, Some("src/main.rs")),
        )
        .expect("file reads are policy-governed for trusted projects");
}

#[test]
fn stale_observed_revision_is_denied_inside_current_epoch() {
    let authority = ProjectTrustPolicyAuthority::new(Arc::new(FakePersistence::with(trusted(5))));
    let mut request = request(SourceChannel::FilesRead, Some("src/main.rs"));
    request.observed_token = Some(TrustToken::new(EPOCH, 4));
    assert_eq!(
        authority.admit_source(project(), request).unwrap_err(),
        TrustAdmissionError::StaleRevision {
            observed: 4,
            current: 5
        }
    );
}

#[test]
fn foreign_epoch_token_is_denied_even_at_same_revision() {
    // F1 regression: a token from a deleted sidecar must not admit through a
    // recreated sidecar even after the same numeric revision was re-granted.
    let authority = ProjectTrustPolicyAuthority::new(Arc::new(FakePersistence::with(trusted(1))));
    let mut request = request(SourceChannel::FilesRead, Some("src/main.rs"));
    request.observed_token = Some(TrustToken::new(EPOCH.wrapping_add(1), 1));
    assert_eq!(
        authority.admit_source(project(), request).unwrap_err(),
        TrustAdmissionError::ForeignEpoch {
            observed_epoch: EPOCH.wrapping_add(1),
            current_epoch: EPOCH
        }
    );
}

#[test]
fn managed_deny_is_never_lifted_by_permission_mode() {
    let record = ProjectTrustRecord {
        status: ProjectTrustStatus::Managed,
        instance_epoch: EPOCH,
        revision: 2,
        managed_deny_mask: SourceChannel::FilesRead.mask_bit(),
    };
    let authority = ProjectTrustPolicyAuthority::new(Arc::new(FakePersistence::with(record)));
    for mode in [
        PermissionMode::Ask,
        PermissionMode::ConfirmForMe,
        PermissionMode::FullAccess,
    ] {
        let mut request = request(SourceChannel::FilesRead, Some("src/main.rs"));
        request.permission_mode = mode;
        assert_eq!(
            authority.admit_source(project(), request).unwrap_err(),
            TrustAdmissionError::DeniedByPolicy {
                reason: SourceDenyReason::ManagedDeny
            },
            "managed deny must survive {mode:?}"
        );
    }
}

#[test]
fn file_read_requires_explicit_path() {
    let authority = ProjectTrustPolicyAuthority::new(Arc::new(FakePersistence::with(trusted(1))));
    assert_eq!(
        authority
            .admit_source(project(), request(SourceChannel::FilesRead, None))
            .unwrap_err(),
        TrustAdmissionError::MissingPath
    );
    let listing = authority
        .admit_source(project(), request(SourceChannel::FilesList, None))
        .expect("root listing carries no path by design");
    assert_eq!(listing.token, TrustToken::new(EPOCH, 1));
}

#[test]
fn authority_failures_are_fail_closed() {
    let failing = ProjectTrustPolicyAuthority::new(Arc::new(FakePersistence::failing()));
    assert_eq!(
        failing
            .admit_source(project(), request(SourceChannel::FilesRead, Some("a.rs")))
            .unwrap_err(),
        TrustAdmissionError::AuthorityUnavailable
    );
    let with_inspection = failing.with_byte_inspection(Arc::new(UnavailableInspection));
    assert_eq!(
        with_inspection
            .inspect(CanonicalContentBoundary::OutboundDelivery, b"bytes")
            .unwrap_err(),
        TrustAdmissionError::AuthorityUnavailable
    );
    let no_inspection =
        ProjectTrustPolicyAuthority::new(Arc::new(FakePersistence::with(trusted(1))));
    assert_eq!(
        no_inspection
            .inspect(CanonicalContentBoundary::CanonicalMutation, b"")
            .unwrap_err(),
        TrustAdmissionError::AuthorityUnavailable
    );
}

#[test]
fn inspect_delegates_to_secret_guard_and_maps_dispositions() {
    let guard = Arc::new(WorkingInspection::new());
    let authority = ProjectTrustPolicyAuthority::new(Arc::new(FakePersistence::with(trusted(1))))
        .with_byte_inspection(guard.clone());
    assert_eq!(
        authority
            .inspect(CanonicalContentBoundary::CanonicalMutation, b"")
            .unwrap(),
        ContentDisposition::Allowed { policy_epoch: 9 }
    );
    assert_eq!(
        authority
            .inspect(CanonicalContentBoundary::OutboundDelivery, b"x")
            .unwrap(),
        ContentDisposition::Prohibited { policy_epoch: 9 }
    );
    assert_eq!(
        *guard.calls.lock().unwrap(),
        2,
        "stage-2 must delegate, not stub"
    );
}

#[test]
fn path_deny_maps_to_typed_sensitive_path_error() {
    let authority = ProjectTrustPolicyAuthority::new(Arc::new(FakePersistence::with(trusted(1))));
    assert_eq!(
        authority
            .admit_source(
                project(),
                request(SourceChannel::FilesRead, Some(".ssh/id_rsa"))
            )
            .unwrap_err(),
        TrustAdmissionError::DeniedByPolicy {
            reason: SourceDenyReason::SensitivePath
        }
    );
    assert_eq!(
        authority
            .admit_source(
                project(),
                request(SourceChannel::FilesRead, Some("../escape"))
            )
            .unwrap_err(),
        TrustAdmissionError::AmbiguousPath
    );
    let admitted = authority
        .admit_source(
            project(),
            request(SourceChannel::FilesRead, Some("src/main.rs")),
        )
        .expect("clean path admitted");
    assert_eq!(admitted.policy_version, 1);
    assert_eq!(admitted.token, TrustToken::new(EPOCH, 1));
}
