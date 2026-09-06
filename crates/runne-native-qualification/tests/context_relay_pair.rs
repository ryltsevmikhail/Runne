#[path = "support/context_relay_fixture.rs"]
mod fixture;

use runne_api::{
    LaunchSecret, QualificationFaultRelayBindingV1, QualificationFaultRelayDirectionV1,
    QualificationRunContextRelayBindingV1, QualificationRunContextRelayDirectionV1,
};
use runne_native_qualification::{
    PendingQualificationAdmission, QualificationFaultRelayCodecV1,
    QualificationRunContextRelayCodecV1,
};

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
    let ticket = fixture::ticket(0x11);
    let context = fixture::context(&ticket, 0x33);
    PendingQualificationAdmission::from_admitted_bundle(fixture::admission_bundle(
        &context, &ticket,
    ))
    .unwrap()
}

#[test]
fn admission_pair_rejects_mixed_transport_bindings_but_allows_independent_sequences() {
    let keys = LaunchSecret::from_bytes([7; 32]).unwrap().derive_keys();
    let context_codec = QualificationRunContextRelayCodecV1::from_protected_activation(&keys);
    let fault_codec = QualificationFaultRelayCodecV1::from_protected_activation(&keys);
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
                .encode_relays(
                    &context_codec,
                    &context_binding(1, 2, 3, 4),
                    &fault_codec,
                    &fault,
                )
                .is_err()
        );
    }
    let [context, fault] = admission()
        .encode_relays(
            &context_codec,
            &context_binding(1, 2, 3, 4),
            &fault_codec,
            &fault_binding(
                1,
                2,
                3,
                QualificationFaultRelayDirectionV1::DesktopToRuntime,
                8,
            ),
        )
        .unwrap()
        .into_ordered_frames();
    context_codec
        .decode(&context, &context_binding(1, 2, 3, 4))
        .unwrap();
    assert!(
        fault_codec
            .decode(
                &fault,
                &fault_binding(
                    1,
                    2,
                    3,
                    QualificationFaultRelayDirectionV1::DesktopToRuntime,
                    8,
                ),
            )
            .unwrap()
            .is_some()
    );
}
