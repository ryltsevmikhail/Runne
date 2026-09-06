use std::io::{Read as _, Write as _};
use std::os::unix::net::UnixStream;

use runne_api::{
    LaunchSecret, QualificationFaultRelayBindingV1, QualificationFaultRelayDirectionV1,
};
use runne_native_qualification::PendingQualificationFault;

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

#[test]
fn absent_ticket_writes_no_frame_and_present_ticket_is_first_and_one_shot() {
    let keys = LaunchSecret::from_bytes([7; 32]).unwrap().derive_keys();
    let (mut peer, mut channel) = UnixStream::pair().unwrap();
    peer.set_nonblocking(true).unwrap();
    assert!(!write_initial_qualification_relay(&mut channel, &keys, binding(), None).unwrap());
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

    let pending = PendingQualificationFault::from_admitted_frame(TICKET.to_vec()).unwrap();
    assert!(
        write_initial_qualification_relay(&mut channel, &keys, binding(), Some(pending)).unwrap()
    );
    let mut prefix = [0; 4];
    peer.read_exact(&mut prefix).unwrap();
    let mut payload = vec![0; u32::from_be_bytes(prefix) as usize];
    peer.read_exact(&mut payload).unwrap();
    assert_eq!(&payload[..8], b"RNQFRLY1");
    peer.set_nonblocking(true).unwrap();
    assert!(
        matches!(peer.read(&mut [0; 1]), Err(error) if error.kind() == std::io::ErrorKind::WouldBlock)
    );
}
