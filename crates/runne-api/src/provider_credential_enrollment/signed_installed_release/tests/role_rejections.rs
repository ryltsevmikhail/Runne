use super::super::{SignedInstalledReleaseVerificationErrorV2 as Error, UpdateMetadataV2};
use super::known_answers::metadata;
use super::release_rejections::verify;

type MetadataMutation = fn(&mut UpdateMetadataV2);

#[test]
fn every_role_link_and_time_boundary_fails_closed() {
    let cases: [(MetadataMutation, Error); 16] = [
        (|value| value.schema_version = 1, Error::InvalidMetadata),
        (|value| value.root.version = 0, Error::InvalidMetadata),
        (
            |value| value.root.schema_version = 1,
            Error::InvalidMetadata,
        ),
        (|value| value.root.threshold = 1, Error::InvalidMetadata),
        (
            |value| value.root.key_ids.swap(0, 1),
            Error::InvalidMetadata,
        ),
        (
            |value| {
                value.root.key_ids.pop();
            },
            Error::InvalidMetadata,
        ),
        (|value| value.targets.version = 0, Error::InvalidMetadata),
        (|value| value.snapshot.version = 0, Error::InvalidMetadata),
        (|value| value.timestamp.version = 0, Error::InvalidMetadata),
        (
            |value| value.snapshot.targets_version += 1,
            Error::InvalidMetadata,
        ),
        (
            |value| value.timestamp.snapshot_version += 1,
            Error::InvalidMetadata,
        ),
        (
            |value| value.targets.target.published_at_unix_seconds = 101,
            Error::Expired,
        ),
        (
            |value| value.targets.expires_at_unix_seconds = 100,
            Error::Expired,
        ),
        (
            |value| value.snapshot.expires_at_unix_seconds = 100,
            Error::Expired,
        ),
        (
            |value| value.timestamp.expires_at_unix_seconds = 100,
            Error::Expired,
        ),
        (
            |value| value.targets.target.expires_at_unix_seconds = 100,
            Error::Expired,
        ),
    ];
    for (mutate, expected) in cases {
        let mut candidate = metadata();
        mutate(&mut candidate);
        assert_eq!(verify(&candidate), Err(expected));
    }
    let mut snapshot = metadata();
    snapshot.snapshot_signature = "00".repeat(64);
    assert_eq!(verify(&snapshot), Err(Error::SnapshotSignature));
    let mut timestamp = metadata();
    timestamp.timestamp_signature = "00".repeat(64);
    assert_eq!(verify(&timestamp), Err(Error::TimestampSignature));
}

#[test]
fn every_signed_role_rejects_an_isolated_unsigned_body_mutation() {
    let mut root = metadata();
    root.root.version = 2;
    assert_eq!(verify(&root), Err(Error::RootQuorum));

    let mut targets = metadata();
    targets.targets.target.channel = "beta".into();
    assert_eq!(verify(&targets), Err(Error::TargetsQuorum));

    let mut snapshot = metadata();
    snapshot.snapshot.expires_at_unix_seconds = 499;
    assert_eq!(verify(&snapshot), Err(Error::SnapshotSignature));

    let mut timestamp = metadata();
    timestamp.timestamp.expires_at_unix_seconds = 499;
    assert_eq!(verify(&timestamp), Err(Error::TimestampSignature));
}
