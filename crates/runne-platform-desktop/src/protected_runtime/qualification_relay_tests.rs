use std::io::{Read as _, Write as _};
use std::os::unix::net::UnixStream;

use runne_api::{
    LaunchSecret, QualificationFaultRelayBindingV1, QualificationFaultRelayDirectionV1,
    QualificationRunContextRelayBindingV1, QualificationRunContextRelayDirectionV1,
};
use runne_native_qualification::PendingQualificationAdmission;
use sha2::{Digest as _, Sha256};

use super::qualification_relay::write_initial_qualification_relay;

const TICKET: &[u8] = br#"{"schema_version":"runne/macos-xpc-dpk-fault-ticket/v1","ticket_id":"1111111111111111111111111111111111111111111111111111111111111111","selector":"kill_desktop_process","process_role":"desktop","candidate_sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","release_tuple_v3_sha256":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","source_revision":"cccccccccccccccccccccccccccccccccccccccc","workflow_run_id":"run-42","namespace_sha256":"dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd","issued_at":1800000000,"expires_at":1800000600,"nonce":"IiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiI","signature":{"algorithm":"ed25519","key_id":"eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee","value":"MzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMw"}}"#;

fn binding() -> QualificationFaultRelayBindingV1 {
    QualificationFaultRelayBindingV1::new(
        [0x71, 1, 1, 1, 1, 1, 0x71, 1, 0x81, 1, 1, 1, 1, 1, 1, 1],
        [2; 32],
        3,
        QualificationFaultRelayDirectionV1::DesktopToRuntime,
        1,
    )
    .unwrap()
}

fn context_binding() -> QualificationRunContextRelayBindingV1 {
    QualificationRunContextRelayBindingV1::new(
        [0x71, 1, 1, 1, 1, 1, 0x71, 1, 0x81, 1, 1, 1, 1, 1, 1, 1],
        [2; 32],
        3,
        QualificationRunContextRelayDirectionV1::DesktopToRuntime,
        1,
    )
    .unwrap()
}

fn admission() -> PendingQualificationAdmission {
    let ticket_sha256 = hex::encode(Sha256::digest(TICKET));
    let context = format!(
        "{{\"schema_version\":\"runne/macos-xpc-dpk-run-context/v1\",\"context_id\":\"{}\",\"scenario_id\":\"macos-xpc-dpk-v1\",\"selector\":\"kill_desktop_process\",\"process_role\":\"desktop\",\"candidate_sha256\":\"{}\",\"release_tuple_v3_sha256\":\"{}\",\"source_revision\":\"{}\",\"workflow_run_id\":\"run-42\",\"namespace_sha256\":\"{}\",\"ticket_sha256\":\"{ticket_sha256}\",\"issued_at\":1800000000,\"expires_at\":1800000300,\"nonce\":\"REREREREREREREREREREREREREREREREREREREREREQ\",\"signature\":{{\"algorithm\":\"ed25519\",\"key_id\":\"{}\",\"value\":\"MzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMw\"}}}}",
        "33".repeat(32), "aa".repeat(32), "bb".repeat(32), "cc".repeat(20),
        "dd".repeat(32), "ee".repeat(32),
    ).into_bytes();
    let mut bundle = Vec::with_capacity(17 + context.len() + TICKET.len());
    bundle.extend_from_slice(b"RNQADM1\0");
    bundle.push(1);
    bundle.extend_from_slice(&u32::try_from(context.len()).unwrap().to_be_bytes());
    bundle.extend_from_slice(&u32::try_from(TICKET.len()).unwrap().to_be_bytes());
    bundle.extend_from_slice(&context);
    bundle.extend_from_slice(TICKET);
    PendingQualificationAdmission::from_admitted_bundle(bundle).unwrap()
}

#[test]
fn absent_admission_preserves_request_and_present_is_exact_context_then_fault() {
    let keys = LaunchSecret::from_bytes([7; 32]).unwrap().derive_keys();
    let (mut peer, mut channel) = UnixStream::pair().unwrap();
    peer.set_nonblocking(true).unwrap();
    assert!(!write_initial_qualification_relay(
        &mut channel,
        &keys,
        context_binding(),
        binding(),
        None,
    ).unwrap());
    assert!(
        matches!(peer.read(&mut [0; 1]), Err(error) if error.kind() == std::io::ErrorKind::WouldBlock)
    );
    let old_request = [
        0_u8, 0, 0, 12, b'G', b'C', b'P', b'C', b'E', b'C', b'T', b'L', 1, 2, 3, 4,
    ];
    channel.write_all(&old_request).unwrap();
    peer.set_nonblocking(false).unwrap();
    let mut observed = [0; 16];
    peer.read_exact(&mut observed).unwrap();
    assert_eq!(
        observed, old_request,
        "absent relay changed first request bytes"
    );

    assert!(
        write_initial_qualification_relay(
            &mut channel,
            &keys,
            context_binding(),
            binding(),
            Some(admission()),
        )
        .unwrap()
    );
    for expected_magic in [b"RNQCTX1\0".as_slice(), b"RNQFRLY1".as_slice()] {
        let mut prefix = [0; 4];
        peer.read_exact(&mut prefix).unwrap();
        let mut payload = vec![0; u32::from_be_bytes(prefix) as usize];
        peer.read_exact(&mut payload).unwrap();
        assert_eq!(&payload[..8], expected_magic);
    }
    peer.set_nonblocking(true).unwrap();
    assert!(
        matches!(peer.read(&mut [0; 1]), Err(error) if error.kind() == std::io::ErrorKind::WouldBlock)
    );
}
