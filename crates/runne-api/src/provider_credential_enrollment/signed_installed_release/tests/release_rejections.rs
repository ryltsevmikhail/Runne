use ed25519_dalek::{Signer, SigningKey};

use super::super::{
    NativeEnrollmentQualificationRowV1, NativeEnrollmentTupleV2,
    SignedInstalledReleaseVerificationErrorV2 as Error, UpdateMetadataV2, UpdateSignatureV2,
    verify_exact_signed_installed_release_v2, verify_signed_update_metadata_v2,
};
use super::known_answers::{RELEASE_BINDING, metadata, trust};

fn roots() -> [SigningKey; 3] {
    [
        SigningKey::from_bytes(&[31; 32]),
        SigningKey::from_bytes(&[32; 32]),
        SigningKey::from_bytes(&[33; 32]),
    ]
}

fn sign(key: &SigningKey, value: &impl serde::Serialize) -> String {
    hex::encode(key.sign(&serde_json::to_vec(value).unwrap()).to_bytes())
}

pub(super) fn resign_targets(metadata: &mut UpdateMetadataV2) {
    metadata.targets_signatures = ["root-a", "root-b"]
        .into_iter()
        .zip(roots())
        .map(|(key_id, key)| UpdateSignatureV2 {
            key_id: key_id.into(),
            signature: sign(&key, &metadata.targets),
        })
        .collect();
}

pub(super) fn verify(metadata: &UpdateMetadataV2) -> Result<(), Error> {
    verify_signed_update_metadata_v2(metadata, &trust(), 100).map(|_| ())
}

pub(super) fn canonical(metadata: &UpdateMetadataV2) -> Vec<u8> {
    serde_json::to_vec(metadata).unwrap()
}

fn tuple_value(metadata: &UpdateMetadataV2) -> serde_json::Value {
    serde_json::to_value(&metadata.targets.target.native_enrollment_tuple).unwrap()
}

type JsonMutation = fn(&mut serde_json::Value);

fn replace_tuple(metadata: &mut UpdateMetadataV2, value: serde_json::Value, rebind: bool) {
    let target = metadata.targets.target.clone();
    let mut tuple: NativeEnrollmentTupleV2 = serde_json::from_value(value).unwrap();
    if rebind {
        tuple.test_only_rebind_digest(&target);
    }
    metadata.targets.target.native_enrollment_tuple = Some(tuple);
    resign_targets(metadata);
}

pub(super) fn requalify(
    metadata: &mut UpdateMetadataV2,
    receipt: &str,
    qualified: u64,
    expires: u64,
) {
    let target = metadata.targets.target.clone();
    let mut value = tuple_value(metadata);
    value
        .as_object_mut()
        .unwrap()
        .remove("nativeEnrollmentQualification");
    let tuple: NativeEnrollmentTupleV2 = serde_json::from_value(value).unwrap();
    let row = NativeEnrollmentQualificationRowV1::new(
        &target,
        &tuple,
        receipt.repeat(64),
        qualified,
        expires,
    )
    .unwrap();
    metadata.targets.target.native_enrollment_tuple =
        Some(tuple.with_qualification(&target, row).unwrap());
    resign_targets(metadata);
}

#[test]
fn strict_quorum_rejects_unknown_duplicate_short_and_noncanonical_signatures() {
    for mutate in [
        |metadata: &mut UpdateMetadataV2| metadata.root_signatures.pop().map(drop),
        |metadata: &mut UpdateMetadataV2| {
            metadata.root_signatures[1].key_id = "root-a".into();
            None
        },
        |metadata: &mut UpdateMetadataV2| {
            metadata.root_signatures[0].key_id = "unknown".into();
            None
        },
        |metadata: &mut UpdateMetadataV2| {
            metadata.root_signatures[0].signature.make_ascii_uppercase();
            None
        },
        |metadata: &mut UpdateMetadataV2| {
            metadata.root_signatures[0].signature.pop();
            None
        },
    ] {
        let mut candidate = metadata();
        mutate(&mut candidate);
        assert_eq!(verify(&candidate), Err(Error::RootQuorum));
    }
    let mut too_many = metadata();
    too_many
        .root_signatures
        .extend(too_many.root_signatures.clone());
    assert_eq!(verify(&too_many), Err(Error::RootQuorum));
    for mutate in [
        |metadata: &mut UpdateMetadataV2| metadata.targets_signatures.pop().map(drop),
        |metadata: &mut UpdateMetadataV2| {
            metadata.targets_signatures[1].key_id = "root-a".into();
            None
        },
        |metadata: &mut UpdateMetadataV2| {
            metadata.targets_signatures[0].signature = "00".repeat(64);
            None
        },
    ] {
        let mut candidate = metadata();
        mutate(&mut candidate);
        assert_eq!(verify(&candidate), Err(Error::TargetsQuorum));
    }
    let mut too_many = metadata();
    too_many
        .targets_signatures
        .extend(too_many.targets_signatures.clone());
    assert_eq!(verify(&too_many), Err(Error::TargetsQuorum));
}

#[test]
fn signed_tuple_rejects_digest_artifact_identity_and_target_substitution() {
    let cases: [(JsonMutation, bool); 8] = [
        (|value| value["tupleSha256"] = "".into(), false),
        (|value| value["tupleSha256"] = "0".repeat(64).into(), false),
        (
            |value| value["writerSha256"] = value["daemonSha256"].clone(),
            true,
        ),
        (
            |value| value["desktopSha256"] = value["contractSha256"].clone(),
            true,
        ),
        (
            |value| value["contractSha256"] = "8".repeat(64).into(),
            true,
        ),
        (
            |value| {
                let _ = value.as_object_mut().unwrap().remove("writerCodeIdentity");
            },
            true,
        ),
        (
            |value| value["writerCodeIdentity"] = value["desktopCodeIdentity"].clone(),
            true,
        ),
        (
            |value| value["writerCodeIdentity"]["cdhash"] = "A".repeat(40).into(),
            true,
        ),
    ];
    for (mutate, rebind) in cases {
        let mut candidate = metadata();
        let mut value = tuple_value(&candidate);
        mutate(&mut value);
        replace_tuple(&mut candidate, value, rebind);
        assert_eq!(verify(&candidate), Err(Error::InvalidMetadata));
    }
    let mut candidate = metadata();
    candidate.targets.target.release_candidate_sha256 = "8".repeat(64);
    resign_targets(&mut candidate);
    assert_eq!(verify(&candidate), Err(Error::InvalidMetadata));
}

#[test]
fn missing_tuple_or_artifact_digest_is_rejected_from_raw_metadata() {
    for field in ["tupleSha256", "writerSha256"] {
        let mut raw = serde_json::to_value(metadata()).unwrap();
        raw["targets"]["target"]["nativeEnrollmentTuple"]
            .as_object_mut()
            .unwrap()
            .remove(field);
        assert_eq!(
            verify_exact_signed_installed_release_v2(
                &serde_json::to_vec(&raw).unwrap(),
                &trust(),
                RELEASE_BINDING,
                100,
            ),
            Err(Error::InvalidEncoding)
        );
    }
}

#[test]
fn recomputed_tuple_rejects_a_stale_qualification_binding() {
    let mut candidate = metadata();
    let mut tuple = tuple_value(&candidate);
    tuple["writerSha256"] = "8".repeat(64).into();
    replace_tuple(&mut candidate, tuple, true);
    assert_eq!(verify(&candidate), Err(Error::InvalidMetadata));
}

#[test]
fn qualification_shape_binding_and_temporal_state_are_strict() {
    for (field, replacement) in [
        ("bindingSha256", serde_json::Value::String("0".repeat(64))),
        ("receiptSha256", serde_json::Value::String("8".repeat(63))),
        ("packageKind", serde_json::Value::String("pkg".into())),
        ("platform", serde_json::Value::String("linux".into())),
        ("architecture", serde_json::Value::String("x86_64".into())),
        ("expiresAtUnixSeconds", serde_json::Value::from(501)),
    ] {
        let mut candidate = metadata();
        let mut tuple = tuple_value(&candidate);
        tuple["nativeEnrollmentQualification"][field] = replacement;
        replace_tuple(&mut candidate, tuple, false);
        assert_eq!(verify(&candidate), Err(Error::InvalidMetadata));
    }
    let mut changed_receipt = metadata();
    let mut tuple = tuple_value(&changed_receipt);
    tuple["nativeEnrollmentQualification"]["receiptSha256"] = "8".repeat(64).into();
    replace_tuple(&mut changed_receipt, tuple, false);
    assert_eq!(verify(&changed_receipt), Err(Error::InvalidMetadata));
    let mut absent = metadata();
    let mut tuple = tuple_value(&absent);
    tuple
        .as_object_mut()
        .unwrap()
        .remove("nativeEnrollmentQualification");
    replace_tuple(&mut absent, tuple, false);
    let verified = verify_signed_update_metadata_v2(&absent, &trust(), 100).unwrap();
    assert!(verified.qualified_release_candidate().is_none());
    assert_eq!(
        verify_exact_signed_installed_release_v2(
            &canonical(&absent),
            &trust(),
            RELEASE_BINDING,
            100
        ),
        Err(Error::Unqualified)
    );
    for (qualified, expires) in [(101, 200), (99, 100)] {
        let mut candidate = metadata();
        requalify(&mut candidate, "8", qualified, expires);
        let verified = verify_signed_update_metadata_v2(&candidate, &trust(), 100).unwrap();
        assert!(verified.qualified_release_candidate().is_none());
        assert_eq!(
            verify_exact_signed_installed_release_v2(
                &canonical(&candidate),
                &trust(),
                RELEASE_BINDING,
                100
            ),
            Err(Error::Unqualified)
        );
    }
}
