use super::super::{
    SignedInstalledReleaseVerificationErrorV2 as Error, UpdateTrustRootV2,
    verify_signed_update_metadata_v2,
};
use super::known_answers::{metadata, trust};
use ed25519_dalek::VerifyingKey;

fn verify(candidate: &UpdateTrustRootV2) -> Result<(), Error> {
    verify_signed_update_metadata_v2(&metadata(), candidate, 100).map(|_| ())
}

#[test]
fn trust_ids_are_bounded_valid_and_globally_distinct() {
    let valid = trust();
    let roots = [
        ("root-a", valid.root_keys[0].public_key),
        ("root-b", valid.root_keys[1].public_key),
        ("root-c", valid.root_keys[2].public_key),
    ];
    let too_long = "a".repeat(65);
    for bad in ["", "a/b", "a b", too_long.as_str()] {
        let candidate = UpdateTrustRootV2::from_keys(
            [(bad, roots[0].1), roots[1], roots[2]],
            ("timestamp", valid.timestamp_key.public_key),
            ("snapshot", valid.snapshot_key.public_key),
        );
        assert_eq!(verify(&candidate), Err(Error::InvalidTrustRoot));
    }
    for (timestamp_id, snapshot_id) in [("root-a", "snapshot"), ("same", "same")] {
        let candidate = UpdateTrustRootV2::from_keys(
            roots,
            (timestamp_id, valid.timestamp_key.public_key),
            (snapshot_id, valid.snapshot_key.public_key),
        );
        assert_eq!(verify(&candidate), Err(Error::InvalidTrustRoot));
    }
    let duplicate_root = UpdateTrustRootV2::from_keys(
        [("root-a", roots[0].1), ("root-a", roots[1].1), roots[2]],
        ("timestamp", valid.timestamp_key.public_key),
        ("snapshot", valid.snapshot_key.public_key),
    );
    assert_eq!(verify(&duplicate_root), Err(Error::InvalidTrustRoot));
}

#[test]
fn trust_key_material_is_valid_and_globally_distinct() {
    let valid = trust();
    let root_a = valid.root_keys[0].public_key;
    let root_b = valid.root_keys[1].public_key;
    let root_c = valid.root_keys[2].public_key;
    let invalid = (0_u8..=u8::MAX)
        .map(|byte| [byte; 32])
        .find(|key| VerifyingKey::from_bytes(key).is_err())
        .expect("Ed25519 has rejected encodings");
    for candidate in [
        UpdateTrustRootV2::from_keys(
            [("root-a", root_a), ("root-b", root_a), ("root-c", root_c)],
            ("timestamp", valid.timestamp_key.public_key),
            ("snapshot", valid.snapshot_key.public_key),
        ),
        UpdateTrustRootV2::from_keys(
            [("root-a", root_a), ("root-b", root_b), ("root-c", root_c)],
            ("timestamp", root_a),
            ("snapshot", valid.snapshot_key.public_key),
        ),
        UpdateTrustRootV2::from_keys(
            [("root-a", root_a), ("root-b", root_b), ("root-c", root_c)],
            ("timestamp", valid.timestamp_key.public_key),
            ("snapshot", valid.timestamp_key.public_key),
        ),
        UpdateTrustRootV2::from_keys(
            [("root-a", invalid), ("root-b", root_b), ("root-c", root_c)],
            ("timestamp", valid.timestamp_key.public_key),
            ("snapshot", valid.snapshot_key.public_key),
        ),
    ] {
        assert_eq!(verify(&candidate), Err(Error::InvalidTrustRoot));
    }
}
