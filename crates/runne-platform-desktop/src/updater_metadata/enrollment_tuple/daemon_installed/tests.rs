use std::time::{SystemTime, UNIX_EPOCH};

use crate::updater_installed_metadata::InstalledUpdateMetadataJournal;

use super::*;

#[path = "tests/measurement_capture.rs"]
mod measurement_capture;
#[path = "tests/fixture_signing.rs"]
mod fixture_signing;
#[path = "tests/fixture.rs"]
mod fixture;

use fixture::{
    FixtureIdentity, RejectingIdentity, commit_record, fixture, input, verify,
};
pub(in crate::updater_metadata) use fixture::signed_fixture_admission;

#[test]
fn fixture_composition_admits_only_a_current_signed_qualified_release() {
    let fixture = fixture(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 60,
    );
    assert!(fixture.paths.measure().is_ok());
    let admission = verified_admission(
        &fixture.profile,
        &fixture.paths,
        &fixture.trust,
        &fixture.policy,
    )
    .unwrap();
    assert!(FixtureIdentity.confirm(&fixture.paths, &admission));
    assert!(
        admission.qualification.matches_exact(
            fixture.release,
            fixture.qualification,
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs()
        ),
        "{:?}",
        admission.qualification
    );
    assert!(verify(&fixture).is_some());
    assert!(
        verify_with(
            &input(&fixture, fixture.release, fixture.qualification),
            &RejectingIdentity,
            || {}
        )
        .is_none()
    );
    assert!(
        verify_with(
            &input(&fixture, [0; 32], fixture.qualification),
            &FixtureIdentity,
            || {}
        )
        .is_none()
    );
    assert!(
        verify_with(
            &input(&fixture, fixture.release, [0; 32]),
            &FixtureIdentity,
            || {}
        )
        .is_none()
    );
}

#[test]
fn qualified_admission_retains_distinct_measurement_sources() {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let fixture = fixture(now + 60);
    let admission = verified_admission(
        &fixture.profile,
        &fixture.paths,
        &fixture.trust,
        &fixture.policy,
    )
    .unwrap();
    let candidate = admission.candidate_source_sha256.unwrap();
    let manifest = admission.target_manifest_sha256.unwrap();
    let qualification = admission
        .qualification
        .retained_qualification_binding_digest()
        .unwrap();
    let sources = [
        candidate,
        manifest,
        qualification,
        admission.release_tuple_sha256,
    ];
    for (index, source) in sources.iter().enumerate() {
        assert!(sources[index + 1..].iter().all(|other| other != source));
    }
}

#[test]
fn fixture_composition_closes_for_noncommitted_corrupt_binding_rollback_or_expiry() {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let first = fixture(now + 60);
    first.journal.clear().unwrap();
    assert!(verify(&first).is_none());
    let binding = fixture(now + 60);
    binding.journal.clear().unwrap();
    commit_record(
        &binding.journal,
        &binding.profile.join("updates"),
        &binding.artifact,
        &"0".repeat(64),
    );
    assert!(verify(&binding).is_none());
    let second = fixture(now + 60);
    std::fs::write(&second.metadata_path, b"{").unwrap();
    assert!(verify(&second).is_none());
    let third = fixture(now + 60);
    third.trust_journal.accept_metadata(8, 10, "1.2.0").unwrap();
    assert!(verify(&third).is_none());
    let expired = fixture(now + 60);
    assert!(
        verified_admission_at(
            &expired.profile,
            &expired.paths,
            &expired.trust,
            &expired.policy,
            now + 61
        )
        .is_none()
    );
}

#[test]
fn final_phase_closes_when_journal_or_artifacts_change() {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let first = fixture(now + 60);
    assert!(
        verify_with(
            &input(&first, first.release, first.qualification),
            &FixtureIdentity,
            || first.journal.clear().unwrap()
        )
        .is_none()
    );
    let second = fixture(now + 60);
    assert!(
        verify_with(
            &input(&second, second.release, second.qualification),
            &FixtureIdentity,
            || std::fs::write(&second.daemon, b"changed").unwrap()
        )
        .is_none()
    );
    let third = fixture(now + 60);
    assert!(
        verify_with(
            &input(&third, third.release, third.qualification),
            &FixtureIdentity,
            || std::fs::write(&third.contract, b"changed").unwrap()
        )
        .is_none()
    );
}

#[test]
fn retained_admission_refresh_closes_after_mint_journal_trust_or_expiry_change() {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let journal = fixture(now + 60);
    let retained = verified_admission(
        &journal.profile,
        &journal.paths,
        &journal.trust,
        &journal.policy,
    )
    .unwrap();
    assert!(
        refresh_retained_admission_at(
            &journal.profile,
            &journal.paths,
            &journal.trust,
            &journal.policy,
            &retained,
            now
        )
        .is_some()
    );
    journal.journal.clear().unwrap();
    assert!(
        refresh_retained_admission_at(
            &journal.profile,
            &journal.paths,
            &journal.trust,
            &journal.policy,
            &retained,
            now
        )
        .is_none()
    );

    let trust = fixture(now + 60);
    let retained =
        verified_admission(&trust.profile, &trust.paths, &trust.trust, &trust.policy).unwrap();
    trust.trust_journal.accept_metadata(8, 10, "1.2.0").unwrap();
    assert!(
        refresh_retained_admission_at(
            &trust.profile,
            &trust.paths,
            &trust.trust,
            &trust.policy,
            &retained,
            now
        )
        .is_none()
    );

    let expiry = fixture(now + 60);
    let retained = verified_admission(
        &expiry.profile,
        &expiry.paths,
        &expiry.trust,
        &expiry.policy,
    )
    .unwrap();
    assert!(
        refresh_retained_admission_at(
            &expiry.profile,
            &expiry.paths,
            &expiry.trust,
            &expiry.policy,
            &retained,
            now + 61
        )
        .is_none()
    );
}
