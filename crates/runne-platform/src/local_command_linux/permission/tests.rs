use super::{super::snapshot::SealedExecutableSnapshot, codec};
use runne_domain::task_run::{TaskRunExecutable, TaskRunLocalCommand};
use std::os::unix::fs::PermissionsExt;

fn command() -> TaskRunLocalCommand {
    TaskRunLocalCommand::new(
        TaskRunExecutable::workspace_relative("bin/tool".into()).unwrap(),
        ".".into(),
        vec!["bin/tool".into(), "--check".into()],
        vec![("B".into(), "2".into()), ("A".into(), "1".into())],
    )
    .unwrap()
}

#[test]
fn closed_schema_and_sorted_environment_match_independent_vectors() {
    assert_eq!(
        hex(&codec::schema_digest()),
        "e0e0ff8d1691c36bb899e2c8625d6bce93ffb69ad1b2aca9cbe3cf536a654ad8"
    );
    assert_eq!(
        hex(&codec::environment_digest(&command()).unwrap()),
        "00c06d3bec738112a014abdf2b74d901e0be63bdd7b893c815669a405d56667e"
    );
}

#[test]
fn target_identity_matches_the_independent_fixed_byte_vector() {
    let digest = codec::target_identity(
        [0, 0, 0, 0, 0, 0, 0x70, 0, 0x80, 0, 0, 0, 0, 0, 0, 7],
        1,
        [0x11; 32],
        [0x22; 32],
        [
            0x8e, 0x70, 0x4f, 0x8a, 0x01, 0x1f, 0x40, 0x5d, 0x54, 0xfd, 0x54, 0xe2, 0x58, 0x55,
            0xa8, 0xc3, 0x82, 0x7f, 0x0e, 0x16, 0x61, 0xfc, 0x45, 0x8e, 0xbe, 0x54, 0x7e, 0x9b,
            0xfd, 0x7a, 0x7f, 0x45,
        ],
    );
    assert_eq!(
        hex(&digest),
        "b8dfcdcf008852fb633746c8aab3c154b4c460214ade1b252500e956221a49f5"
    );
}

#[test]
fn identical_executable_bytes_in_distinct_sealed_objects_have_distinct_targets() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("program");
    std::fs::write(&path, b"identical sealed program").unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
    let source = std::fs::File::open(&path).unwrap();
    let workspace = std::fs::File::open(std::env::temp_dir()).unwrap();
    let first = SealedExecutableSnapshot::from_held_file(&source).unwrap();
    let second = SealedExecutableSnapshot::from_held_file(&source).unwrap();
    let first_target = codec::target_digest(&first, &workspace, &workspace).unwrap();
    let second_target = codec::target_digest(&second, &workspace, &workspace).unwrap();
    assert_ne!(first_target.0, second_target.0);
    assert_eq!(first.permission_identity().1, 1);
    assert_eq!(second.permission_identity().1, 1);
}

fn hex(value: &[u8]) -> String {
    value.iter().map(|byte| format!("{byte:02x}")).collect()
}
