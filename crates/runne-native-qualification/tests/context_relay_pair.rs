#[path = "support/context_relay_fixture.rs"]
mod fixture;

use runne_api::{
    LaunchSecret, QualificationFaultRelayAuthenticator, QualificationFaultRelayBindingV1,
    QualificationFaultRelayDirectionV1, QualificationFaultRelayTicketBindingV1,
    QualificationRunContextRelayAuthenticator, QualificationRunContextRelayBindingV1,
    QualificationRunContextRelayContentBindingV1, QualificationRunContextRelayDirectionV1,
};
use runne_native_qualification::{
    PendingQualificationAdmission, QualificationAdmissionRelayCodecV1,
    QualificationFaultRelayCodecV1, QualificationRunContextRelayCodecV1,
};
use sha2::{Digest as _, Sha256};

const fn session(byte: u8) -> [u8; 16] {
    [
        0x71, byte, byte, byte, byte, byte, 0x71, byte, 0x81, byte, byte, byte, byte, byte, byte,
        byte,
    ]
}

fn context_binding(
    session_byte: u8,
    release_byte: u8,
    generation: u64,
    sequence: u64,
) -> QualificationRunContextRelayBindingV1 {
    QualificationRunContextRelayBindingV1::new(
        session(session_byte),
        [release_byte; 32],
        generation,
        QualificationRunContextRelayDirectionV1::DesktopToRuntime,
        sequence,
    )
    .unwrap()
}

fn fault_binding(
    session_byte: u8,
    release_byte: u8,
    generation: u64,
    direction: QualificationFaultRelayDirectionV1,
    sequence: u64,
) -> QualificationFaultRelayBindingV1 {
    QualificationFaultRelayBindingV1::new(
        session(session_byte),
        [release_byte; 32],
        generation,
        direction,
        sequence,
    )
    .unwrap()
}

fn admission() -> PendingQualificationAdmission {
    admission_with(0x11)
}

fn admission_with(id: u8) -> PendingQualificationAdmission {
    let ticket = fixture::ticket(id);
    let context = fixture::context(&ticket, id);
    PendingQualificationAdmission::from_admitted_bundle(fixture::admission_bundle(
        &context, &ticket,
    ))
    .unwrap()
}

fn exact_fault() -> QualificationFaultRelayBindingV1 {
    fault_binding(
        1,
        2,
        3,
        QualificationFaultRelayDirectionV1::DesktopToRuntime,
        8,
    )
}

fn authenticated_context_frame(
    keys: &runne_api::ProtectedActivationKeys,
    binding: &QualificationRunContextRelayBindingV1,
    context: &[u8],
) -> Vec<u8> {
    let mac_content = QualificationRunContextRelayContentBindingV1::new(
        u32::try_from(context.len()).unwrap(),
        Sha256::digest(context).into(),
    )
    .unwrap();
    let mut frame = Vec::new();
    frame.extend_from_slice(b"RNQCTX1\0");
    frame.push(1);
    frame.push(binding.direction().wire_tag());
    frame.extend_from_slice(&binding.protected_session_id());
    frame.extend_from_slice(&binding.release_tuple_v3_sha256());
    frame.extend_from_slice(&binding.launch_generation().to_be_bytes());
    frame.extend_from_slice(&binding.sequence().to_be_bytes());
    frame.extend_from_slice(&u32::try_from(context.len()).unwrap().to_be_bytes());
    frame.extend_from_slice(context);
    frame.extend_from_slice(
        &QualificationRunContextRelayAuthenticator::from_protected_activation(keys)
            .authenticate(binding, &mac_content),
    );
    frame
}

fn authenticated_fault_frame(
    keys: &runne_api::ProtectedActivationKeys,
    binding: &QualificationFaultRelayBindingV1,
    ticket: &[u8],
) -> Vec<u8> {
    let mac_content = QualificationFaultRelayTicketBindingV1::present(
        u32::try_from(ticket.len()).unwrap(),
        Sha256::digest(ticket).into(),
    )
    .unwrap();
    let mut frame = Vec::new();
    frame.extend_from_slice(b"RNQFRLY1");
    frame.push(1);
    frame.push(binding.direction().wire_tag());
    frame.extend_from_slice(&binding.protected_session_id());
    frame.extend_from_slice(&binding.release_tuple_v3_sha256());
    frame.extend_from_slice(&binding.launch_generation().to_be_bytes());
    frame.extend_from_slice(&binding.sequence().to_be_bytes());
    frame.push(1);
    frame.extend_from_slice(&u32::try_from(ticket.len()).unwrap().to_be_bytes());
    frame.extend_from_slice(ticket);
    frame.extend_from_slice(
        &QualificationFaultRelayAuthenticator::from_protected_activation(keys)
            .authenticate(binding, &mac_content),
    );
    frame
}

fn relay_transcript(context_frame: &[u8], fault_frame: &[u8]) -> Vec<u8> {
    let mut transcript = Vec::new();
    for frame in [context_frame, fault_frame] {
        transcript.extend_from_slice(&u32::try_from(frame.len()).unwrap().to_be_bytes());
        transcript.extend_from_slice(frame);
    }
    transcript
}

#[test]
fn transcript_rejects_mixed_bindings_but_allows_independent_sequences() {
    let keys = LaunchSecret::from_bytes([7; 32]).unwrap().derive_keys();
    let codec = QualificationAdmissionRelayCodecV1::from_protected_activation(&keys);
    for fault in [
        fault_binding(
            9,
            2,
            3,
            QualificationFaultRelayDirectionV1::DesktopToRuntime,
            8,
        ),
        fault_binding(
            1,
            9,
            3,
            QualificationFaultRelayDirectionV1::DesktopToRuntime,
            8,
        ),
        fault_binding(
            1,
            2,
            9,
            QualificationFaultRelayDirectionV1::DesktopToRuntime,
            8,
        ),
        fault_binding(
            1,
            2,
            3,
            QualificationFaultRelayDirectionV1::RuntimeToWriter,
            8,
        ),
    ] {
        assert!(
            admission()
                .encode_relay_transcript(&codec, &context_binding(1, 2, 3, 4), &fault)
                .is_err()
        );
    }
    let transcript = admission()
        .encode_relay_transcript(&codec, &context_binding(1, 2, 3, 4), &exact_fault())
        .unwrap()
        .into_bytes();
    codec
        .decode_transcript(&transcript, &context_binding(1, 2, 3, 4), &exact_fault())
        .unwrap();
}

#[test]
fn mixed_activation_members_and_transcript_edits_fail_closed() {
    let first_keys = LaunchSecret::from_bytes([7; 32]).unwrap().derive_keys();
    let second_keys = LaunchSecret::from_bytes([8; 32]).unwrap().derive_keys();
    let first_codec = QualificationAdmissionRelayCodecV1::from_protected_activation(&first_keys);
    let second_codec = QualificationAdmissionRelayCodecV1::from_protected_activation(&second_keys);
    let exact_context = context_binding(1, 2, 3, 4);
    let exact_fault = exact_fault();
    let first = admission()
        .encode_relay_transcript(&first_codec, &exact_context, &exact_fault)
        .unwrap()
        .into_bytes();
    let second = admission()
        .encode_relay_transcript(&second_codec, &exact_context, &exact_fault)
        .unwrap()
        .into_bytes();
    let first_context_len =
        usize::try_from(u32::from_be_bytes(first[..4].try_into().unwrap())).unwrap();
    let fault_offset = 4 + first_context_len;
    let mut mixed = first[..fault_offset].to_vec();
    mixed.extend_from_slice(&second[fault_offset..]);
    assert!(
        first_codec
            .decode_transcript(&mixed, &exact_context, &exact_fault)
            .is_err()
    );
    let context_length_prefix = &first[..4];
    let context_end = fault_offset;
    let fault_length_prefix = &first[fault_offset..fault_offset + 4];
    let fault_frame = &first[fault_offset + 4..];
    let mut reordered = Vec::new();
    reordered.extend_from_slice(fault_length_prefix);
    reordered.extend_from_slice(fault_frame);
    reordered.extend_from_slice(context_length_prefix);
    reordered.extend_from_slice(&first[4..context_end]);
    let mut duplicated = Vec::new();
    duplicated.extend_from_slice(context_length_prefix);
    duplicated.extend_from_slice(&first[4..context_end]);
    duplicated.extend_from_slice(context_length_prefix);
    duplicated.extend_from_slice(&first[4..context_end]);
    for edited in [reordered, duplicated] {
        assert!(
            first_codec
                .decode_transcript(&edited, &exact_context, &exact_fault)
                .is_err()
        );
    }
    for edited in [first[..first.len() - 1].to_vec(), first[4..].to_vec()] {
        assert!(
            first_codec
                .decode_transcript(&edited, &exact_context, &exact_fault)
                .is_err()
        );
    }
}

#[test]
fn independently_authenticated_members_cannot_cross_admission_digest_binding() {
    let keys = LaunchSecret::from_bytes([7; 32]).unwrap().derive_keys();
    let codec = QualificationAdmissionRelayCodecV1::from_protected_activation(&keys);
    let exact_context = context_binding(1, 2, 3, 4);
    let exact_fault = exact_fault();
    let first = admission_with(0x11)
        .encode_relay_transcript(&codec, &exact_context, &exact_fault)
        .unwrap()
        .into_bytes();
    let second = admission_with(0x22)
        .encode_relay_transcript(&codec, &exact_context, &exact_fault)
        .unwrap()
        .into_bytes();
    let context_len = usize::try_from(u32::from_be_bytes(first[..4].try_into().unwrap())).unwrap();
    let fault_offset = 4 + context_len;
    let mut crossed = first[..fault_offset].to_vec();
    crossed.extend_from_slice(&second[fault_offset..]);
    assert!(
        codec
            .decode_transcript(&crossed, &exact_context, &exact_fault)
            .is_err()
    );
}

#[test]
fn independently_authenticated_members_reject_context_later_than_ticket() {
    let keys = LaunchSecret::from_bytes([7; 32]).unwrap().derive_keys();
    let context_binding = context_binding(1, 2, 3, 4);
    let fault_binding = exact_fault();
    let ticket = fixture::ticket_with_times(0x11, 1_800_000_000, 1_800_000_300);
    let context = fixture::context_with_times(&ticket, 0x11, 1_800_000_000, 1_800_000_600);
    let context_frame = authenticated_context_frame(&keys, &context_binding, &context);
    let fault_frame = authenticated_fault_frame(&keys, &fault_binding, &ticket);

    QualificationRunContextRelayCodecV1::from_protected_activation(&keys)
        .decode(&context_frame, &context_binding)
        .expect("context has a valid individual time shape and HMAC");
    assert!(
        QualificationFaultRelayCodecV1::from_protected_activation(&keys)
            .decode(&fault_frame, &fault_binding)
            .expect("ticket has a valid individual time shape and HMAC")
            .is_some()
    );
    let transcript = relay_transcript(&context_frame, &fault_frame);
    assert!(
        QualificationAdmissionRelayCodecV1::from_protected_activation(&keys)
            .decode_transcript(&transcript, &context_binding, &fault_binding)
            .is_err(),
        "combined admission must enforce context expiry no later than ticket expiry"
    );
}
