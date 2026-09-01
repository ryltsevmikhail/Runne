use super::*;
use crate::{
    BeginProviderCredentialEnrollment, ProviderCredentialEnrollmentActionV2,
    ProviderCredentialOperationHandleV2, ProviderCredentialOperationKindV2,
    ProviderCredentialOperationSnapshotV2, ProviderCredentialOperationStateV2,
    ProviderCredentialProviderV2,
};

fn codec() -> ProtectedCredentialEnrollmentLifecycleCodec {
    let keys = LaunchSecret::from_bytes([41; 32]).unwrap().derive_keys();
    ProtectedCredentialEnrollmentLifecycleCodec::from_protected_activation(&keys)
}

fn begin() -> BeginProviderCredentialEnrollment {
    BeginProviderCredentialEnrollment::new(
        ProviderCredentialEnrollmentActionV2::Pair,
        ProviderCredentialProviderV2::OpenAi,
        7,
        "00000000-0000-7000-8000-000000000009",
        "credential-v3-internal",
        "native-intent",
    )
    .unwrap()
}

#[test]
fn lifecycle_begin_is_canonical_directional_and_sequence_bound() {
    let codec = codec();
    let frame = codec.encode_desktop_begin(&begin(), 1).unwrap();

    let opened: BeginProviderCredentialEnrollment = codec.decode_desktop_begin(&frame, 0).unwrap();
    assert_eq!(opened, begin());
    let replay: Result<BeginProviderCredentialEnrollment, _> =
        codec.decode_desktop_begin(&frame, 1);
    assert!(replay.is_err());
    let wrong_direction: Result<ProviderCredentialOperationSnapshotV2, _> =
        codec.decode_daemon_snapshot(&frame, 0);
    assert!(wrong_direction.is_err());

    let mut raw = serde_json::to_vec(&begin()).unwrap();
    raw.insert(0, b' ');
    let noncanonical = codec
        .encode(DESKTOP_DIRECTION, BEGIN_KIND, 1, &raw)
        .unwrap();
    let noncanonical: Result<BeginProviderCredentialEnrollment, _> =
        codec.decode_desktop_begin(&noncanonical, 0);
    assert!(noncanonical.is_err());
    let maximum = codec.encode_desktop_begin(&begin(), u64::MAX).unwrap();
    let overflow: Result<BeginProviderCredentialEnrollment, _> =
        codec.decode_desktop_begin(&maximum, u64::MAX);
    assert!(overflow.is_err());
}

#[test]
fn lifecycle_relay_is_daemon_only_bounded_and_digest_acknowledged() {
    let codec = codec();
    let relay = vec![7; 388];
    let frame = codec.encode_daemon_relay(&relay, 2).unwrap();
    let opened = codec.decode_daemon_relay(&frame, 1).unwrap();
    assert_eq!(opened, relay);
    assert!(codec.decode_desktop_relay_ack(&frame, 1, &relay).is_err());

    let acknowledgement = codec.encode_desktop_relay_ack(&relay, 2).unwrap();
    codec
        .decode_desktop_relay_ack(&acknowledgement, 1, &relay)
        .unwrap();
    assert!(
        codec
            .decode_desktop_relay_ack(&acknowledgement, 1, &[8; 388])
            .is_err()
    );
    assert!(codec.encode_daemon_relay(&vec![1; 4097], 2).is_err());
    assert!(codec.encode_daemon_relay(&vec![1; 387], 2).is_err());
    assert!(codec.encode_daemon_relay(&vec![1; 389], 2).is_err());

    let mut trailing = frame;
    trailing.push(0);
    assert!(codec.decode_daemon_relay(&trailing, 1).is_err());
}

#[test]
fn lifecycle_snapshot_surface_is_the_exact_safe_projection() {
    fn accepts_exact(
        codec: &ProtectedCredentialEnrollmentLifecycleCodec,
        snapshot: &ProviderCredentialOperationSnapshotV2,
    ) {
        let frame = codec.encode_daemon_snapshot(snapshot, 1).unwrap();
        let opened: ProviderCredentialOperationSnapshotV2 =
            codec.decode_daemon_snapshot(&frame, 0).unwrap();
        assert_eq!(opened, *snapshot);
        assert_eq!(opened.broker_rendezvous_id(), Some("rendezvous"));
    }
    let prepared = ProviderCredentialOperationSnapshotV2::new(
        ProviderCredentialOperationHandleV2::from_bytes([1; 48]).unwrap(),
        Some("rendezvous".into()),
        ProviderCredentialProviderV2::OpenAi,
        ProviderCredentialOperationKindV2::Pair,
        ProviderCredentialOperationStateV2::Prepared,
        1,
        1,
        false,
        None,
    )
    .unwrap();
    accepts_exact(&codec(), &prepared);
    assert!(
        ProviderCredentialOperationSnapshotV2::new(
            prepared.operation_handle(),
            Some("rendezvous".into()),
            ProviderCredentialProviderV2::OpenAi,
            ProviderCredentialOperationKindV2::Pair,
            ProviderCredentialOperationStateV2::Claimed,
            1,
            1,
            false,
            None,
        )
        .is_err()
    );
}
