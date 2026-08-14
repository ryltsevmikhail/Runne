use std::{collections::BTreeMap, sync::Mutex};

use gocode_project_owner_authority::{
    KeyRotationV1, ProjectOwnerTrustConfigV1, rotation_old_authorization_transcript,
};

use super::tests::{FakeClock, FakeFiles, FakeRng, FakeStore, FakeTty, runner};
use super::{AuthorityCommandRunner, AuthorityFiles, InitRequest, RotateRequest};

#[test]
fn rotation_review_challenge_binds_successor_path_and_bytes() {
    let store = FakeStore::new();
    let files = FakeFiles {
        fail_on_write: Mutex::new(None),
        write_count: Mutex::new(0),
        fail_reads_after_write: false,
        bytes: Mutex::new(BTreeMap::new()),
    };
    let mut rng = FakeRng;
    runner(&store, &files, &mut rng)
        .init(InitRequest {
            trust_out: "docs/trust.json".into(),
        })
        .expect("init");
    let mut rng = FakeRng;
    AuthorityCommandRunner::new(&store, &(), &FakeTty, &mut rng, &FakeClock, &files)
        .rotate(RotateRequest {
            trust_config: "docs/trust.json".into(),
            rotation_out: "docs/evidence/rotation.json".into(),
            successor_trust_out: "docs/successor-trust.json".into(),
        })
        .expect("rotate");
    let old = ProjectOwnerTrustConfigV1::from_json(
        &files.read_repo_public("docs/trust.json").expect("old"),
    )
    .expect("old trust");
    let rotation = KeyRotationV1::from_json(
        &files
            .read_repo_public("docs/evidence/rotation.json")
            .expect("rotation"),
    )
    .expect("rotation");
    let rotation_bytes = files
        .read_repo_public("docs/evidence/rotation.json")
        .expect("rotation");
    let successor_bytes = files
        .read_repo_public("docs/successor-trust.json")
        .expect("successor");
    let payload = rotation_old_authorization_transcript(&rotation).expect("payload");
    let set = |path: &str, bytes: &[u8]| {
        super::output_set::rotation_set(
            super::output_set::OutputArtifact {
                role: "rotation",
                path: "docs/evidence/rotation.json",
                bytes: &rotation_bytes,
            },
            super::output_set::OutputArtifact {
                role: "successor-trust",
                path,
                bytes,
            },
        )
        .expect("set")
    };
    let original = super::rotate::review(
        &old,
        &rotation,
        &set("docs/successor-trust.json", &successor_bytes),
        &payload,
    )
    .expect("review");
    let path_changed = super::rotate::review(
        &old,
        &rotation,
        &set("docs/other-trust.json", &successor_bytes),
        &payload,
    )
    .expect("review");
    let bytes_changed = super::rotate::review(
        &old,
        &rotation,
        &set("docs/successor-trust.json", b"changed\n"),
        &payload,
    )
    .expect("review");
    assert_ne!(
        original.public_display().expect("display"),
        path_changed.public_display().expect("display")
    );
    assert_ne!(
        original.confirmation_challenge().expect("challenge"),
        bytes_changed.confirmation_challenge().expect("challenge")
    );
}
