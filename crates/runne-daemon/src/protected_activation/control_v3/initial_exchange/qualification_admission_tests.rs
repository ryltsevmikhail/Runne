use std::io::Write as _;
use std::os::unix::net::UnixStream;

use ed25519_dalek::SigningKey;
use runne_api::{
    QualificationFaultRelayBindingV1, QualificationFaultRelayDirectionV1,
    QualificationRunContextRelayBindingV1, QualificationRunContextRelayDirectionV1,
};
use runne_native_qualification::{
    QualificationAdmissionRelayCodecV1, QualificationAdmissionVerifier,
    QualificationFaultRelayCodecV1,
};

use super::super::super::ProtectedActivationChannel;
use super::{InitialQualificationFrame, read_initial_qualification};

pub(super) mod support;
use support::*;

fn installed(
    owned: &runne_api::ProtectedCredentialEnrollmentOwnedLaunchV3,
    candidate: [u8; 32],
    raw_tuple: [u8; 32],
) -> runne_platform_desktop::VerifiedInstalledEnrollmentMeasurementFacts {
    runne_platform_desktop::VerifiedInstalledEnrollmentMeasurementFacts::
        test_only_qualification_facts(
            *owned.enrollment_binding().release_tuple_digest(),
            *owned.enrollment_binding().qualification_binding_digest(),
            candidate,
            raw_tuple,
        )
}

#[test]
fn exact_signed_pair_verifies_and_legacy_request_is_preserved() {
    let (owned, keys, _) = crate::protected_activation::enrollment_v3_tests::owned_and_sessions();
    let context_key = SigningKey::from_bytes(&[7; 32]);
    let fault_key = SigningKey::from_bytes(&[9; 32]);
    let installed = installed(&owned, CANDIDATE, RAW_TUPLE);
    let mut verifier = QualificationAdmissionVerifier::test_only_from_verifying_keys(
        context_key.verifying_key(),
        fault_key.verifying_key(),
    );
    let (mut peer, daemon) = UnixStream::pair().unwrap();
    peer.write_all(&relay(&owned, &keys, &context_key, &fault_key))
        .unwrap();
    let mut channel = ProtectedActivationChannel::new(daemon).unwrap();
    assert!(matches!(
        read_initial_qualification(&mut channel, &keys, &owned, &installed, &mut verifier, NOW,)
            .unwrap(),
        InitialQualificationFrame::Verified(_)
    ));

    let request = outer(b"GCPCECTLprevious-request");
    let (mut peer, daemon) = UnixStream::pair().unwrap();
    peer.write_all(&request).unwrap();
    let mut channel = ProtectedActivationChannel::new(daemon).unwrap();
    assert!(matches!(
        read_initial_qualification(
            &mut channel,
            &keys,
            &owned,
            &installed,
            &mut verifier,
            NOW,
        )
        .unwrap(),
        InitialQualificationFrame::Legacy(frame) if *frame == request
    ));
}

#[test]
fn qualification_clock_is_epoch_time_and_boot_duration_cannot_verify() {
    let before = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let observed = super::super::unix_epoch_qualification_clock()().unwrap();
    let after = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    assert!((before..=after).contains(&observed));

    let (owned, keys, _) = crate::protected_activation::enrollment_v3_tests::owned_and_sessions();
    let context_key = SigningKey::from_bytes(&[7; 32]);
    let fault_key = SigningKey::from_bytes(&[9; 32]);
    let installed = installed(&owned, CANDIDATE, RAW_TUPLE);
    for (now, accepted) in [(600, false), (NOW, true)] {
        let (mut peer, daemon) = UnixStream::pair().unwrap();
        peer.write_all(&relay(&owned, &keys, &context_key, &fault_key))
            .unwrap();
        let mut verifier = QualificationAdmissionVerifier::test_only_from_verifying_keys(
            context_key.verifying_key(),
            fault_key.verifying_key(),
        );
        let result = read_initial_qualification(
            &mut ProtectedActivationChannel::new(daemon).unwrap(),
            &keys,
            &owned,
            &installed,
            &mut verifier,
            now,
        );
        assert_eq!(result.is_ok(), accepted);
    }
}

#[test]
fn installed_facts_and_both_authorities_fail_closed_independently() {
    let (owned, keys, _) = crate::protected_activation::enrollment_v3_tests::owned_and_sessions();
    let context_key = SigningKey::from_bytes(&[7; 32]);
    let fault_key = SigningKey::from_bytes(&[9; 32]);
    let wrong_key = SigningKey::from_bytes(&[5; 32]);
    for (facts, mut verifier) in [
        (
            installed(&owned, [0xac; 32], RAW_TUPLE),
            QualificationAdmissionVerifier::test_only_from_verifying_keys(
                context_key.verifying_key(),
                fault_key.verifying_key(),
            ),
        ),
        (
            installed(&owned, CANDIDATE, [0xbc; 32]),
            QualificationAdmissionVerifier::test_only_from_verifying_keys(
                context_key.verifying_key(),
                fault_key.verifying_key(),
            ),
        ),
        (
            installed(&owned, CANDIDATE, RAW_TUPLE),
            QualificationAdmissionVerifier::from_compiled_policy(),
        ),
        (
            installed(&owned, CANDIDATE, RAW_TUPLE),
            QualificationAdmissionVerifier::test_only_from_verifying_keys(
                wrong_key.verifying_key(),
                fault_key.verifying_key(),
            ),
        ),
        (
            installed(&owned, CANDIDATE, RAW_TUPLE),
            QualificationAdmissionVerifier::test_only_from_verifying_keys(
                context_key.verifying_key(),
                wrong_key.verifying_key(),
            ),
        ),
    ] {
        let (mut peer, daemon) = UnixStream::pair().unwrap();
        peer.write_all(&relay(&owned, &keys, &context_key, &fault_key))
            .unwrap();
        assert!(
            read_initial_qualification(
                &mut ProtectedActivationChannel::new(daemon).unwrap(),
                &keys,
                &owned,
                &facts,
                &mut verifier,
                NOW,
            )
            .is_err()
        );
    }
}

#[test]
fn raw_fault_first_and_missing_or_malformed_second_frame_fail_closed() {
    let (owned, keys, _) = crate::protected_activation::enrollment_v3_tests::owned_and_sessions();
    let context_key = SigningKey::from_bytes(&[7; 32]);
    let fault_key = SigningKey::from_bytes(&[9; 32]);
    let installed = installed(&owned, CANDIDATE, RAW_TUPLE);
    let transcript = relay(&owned, &keys, &context_key, &fault_key);
    let first_len = 4 + u32::from_be_bytes(transcript[..4].try_into().unwrap()) as usize;
    let fault = transcript[first_len..].to_vec();
    let mut malformed = transcript.clone();
    *malformed.last_mut().unwrap() ^= 1;
    let reordered = [
        transcript[first_len..].to_vec(),
        transcript[..first_len].to_vec(),
    ]
    .concat();
    let other_keys = runne_api::LaunchSecret::from_bytes([0x55; 32])
        .unwrap()
        .derive_keys();
    let mixed_key = relay(&owned, &other_keys, &context_key, &fault_key);
    let foreign_session = [0x71, 9, 9, 9, 9, 9, 0x71, 9, 0x89, 9, 9, 9, 9, 9, 9, 9];
    let release = *owned.enrollment_binding().release_tuple_digest();
    let crossed_context = QualificationRunContextRelayBindingV1::new(
        foreign_session,
        release,
        owned.launch_generation(),
        QualificationRunContextRelayDirectionV1::DesktopToRuntime,
        1,
    )
    .unwrap();
    let crossed_fault = QualificationFaultRelayBindingV1::new(
        foreign_session,
        release,
        owned.launch_generation(),
        QualificationFaultRelayDirectionV1::DesktopToRuntime,
        1,
    )
    .unwrap();
    let crossed = relay_with_bindings(
        &keys,
        &context_key,
        &fault_key,
        &crossed_context,
        &crossed_fault,
    );
    for bytes in [
        fault,
        transcript[..first_len].to_vec(),
        malformed,
        reordered,
        mixed_key,
        crossed,
    ] {
        let (mut peer, daemon) = UnixStream::pair().unwrap();
        peer.write_all(&bytes).unwrap();
        peer.shutdown(std::net::Shutdown::Write).unwrap();
        let mut verifier = QualificationAdmissionVerifier::test_only_from_verifying_keys(
            context_key.verifying_key(),
            fault_key.verifying_key(),
        );
        assert!(
            read_initial_qualification(
                &mut ProtectedActivationChannel::new(daemon).unwrap(),
                &keys,
                &owned,
                &installed,
                &mut verifier,
                NOW,
            )
            .is_err()
        );
    }

    let (context_binding, fault_binding) = bindings(&owned);
    let raw_fault = admission(&context_key, &fault_key)
        .encode_relay_transcript(
            &QualificationAdmissionRelayCodecV1::from_protected_activation(&keys),
            &context_binding,
            &fault_binding,
        )
        .unwrap()
        .into_bytes();
    assert!(QualificationFaultRelayCodecV1::recognizes_frame(
        &raw_fault[first_len..]
    ));
}
