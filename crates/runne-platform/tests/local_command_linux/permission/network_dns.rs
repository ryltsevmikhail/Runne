use super::network_none::support as none;
use super::network_qualification_support as qualification;
use runne_application::permission_modes::NetworkScope;
use std::ffi::OsString;
use std::fs::File;
use std::net::UdpSocket;
use std::time::Duration;

const DNS_QUERY: &[u8] =
    b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x04test\x00\x00\x01\x00\x01";

#[test]
fn broad_network_scope_completes_controlled_loopback_dns_fixture() {
    eprintln!("RUN: broad_network_scope_completes_controlled_loopback_dns_fixture");
    let fixture = qualification::fixture(NetworkScope::BroadSameUser);
    let marker = fixture.workspace.0.join("broad-dns-before-network");
    let server = UdpSocket::bind(("127.0.0.1", 0)).expect("parent loopback UDP observer");
    server
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let address = server.local_addr().unwrap();
    let mut reply = DNS_QUERY.to_vec();
    reply[2] = 0x81;
    reply[3] = 0x80;
    let query = DNS_QUERY.to_vec();
    let expected_reply = reply.clone();
    let observed = std::thread::scope(|scope| {
        let observer = scope.spawn(move || {
            let mut buffer = [0_u8; 512];
            let (size, peer) = server.recv_from(&mut buffer).expect("child DNS query");
            let packet = buffer[..size].to_vec();
            server
                .send_to(&reply, peer)
                .expect("deterministic DNS reply");
            packet
        });
        let (code, stdout, stderr) = execute_dns(
            &fixture,
            &marker,
            address.port(),
            &query,
            &expected_reply,
            "broad",
        );
        assert_eq!(code, 0, "broad DNS child failed: {stderr:?} {stdout:?}");
        assert!(stderr.is_empty());
        assert_eq!(stdout, b"dns-fixture-reply-observed\n");
        assert_eq!(std::fs::read(&marker).unwrap(), b"broad-dns-before-network");
        observer.join().expect("join finite loopback observer")
    });
    assert_eq!(observed, DNS_QUERY);
    fixture.area.prove_empty().unwrap().revalidate().unwrap();
    fixture.area.remove();
}

#[test]
fn network_none_writes_then_denies_same_dns_query_without_loopback_packet() {
    eprintln!("RUN: network_none_writes_then_denies_same_dns_query_without_loopback_packet");
    let fixture = qualification::fixture(NetworkScope::None);
    let marker = fixture.workspace.0.join("closed-dns-before-denial");
    let server = UdpSocket::bind(("127.0.0.1", 0)).expect("parent loopback UDP observer");
    server
        .set_read_timeout(Some(Duration::from_millis(800)))
        .unwrap();
    let address = server.local_addr().unwrap();
    let query = DNS_QUERY.to_vec();
    let packet = std::thread::scope(|scope| {
        let observer = scope.spawn(move || {
            let mut buffer = [0_u8; 512];
            match server.recv_from(&mut buffer) {
                Ok((size, _)) => Some(buffer[..size].to_vec()),
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => None,
                Err(error) if error.kind() == std::io::ErrorKind::TimedOut => None,
                Err(error) => panic!("loopback observer failed: {error}"),
            }
        });
        let (code, stdout, stderr) =
            execute_dns(&fixture, &marker, address.port(), &query, &[], "closed");
        assert_eq!(code, 0, "closed DNS child failed: {stderr:?} {stdout:?}");
        assert!(stderr.is_empty());
        let output = std::str::from_utf8(&stdout).unwrap();
        assert!(matches!(
            output,
            "dns-socket-denied\n" | "dns-send-denied\n"
        ));
        assert_eq!(std::fs::read(&marker).unwrap(), b"closed-dns-before-denial");
        observer.join().expect("join finite loopback observer")
    });
    assert!(
        packet.is_none(),
        "closed-network child reached parent UDP observer"
    );
    fixture.area.prove_empty().unwrap().revalidate().unwrap();
    fixture.area.remove();
}

fn execute_dns(
    fixture: &none::Fixture,
    marker: &std::path::Path,
    port: u16,
    query: &[u8],
    reply: &[u8],
    mode: &str,
) -> (i32, Vec<u8>, Vec<u8>) {
    let executable = File::open("/usr/bin/python3").expect("Python executable");
    let sealed =
        runne_platform::local_command_linux::SealedExecutableSnapshot::from_held_file(&executable)
            .expect("sealed Python");
    let script = if mode == "broad" {
        r#"
import socket, sys
path, port, query_hex, reply_hex = sys.argv[1:]
with open(path, 'wb') as marker: marker.write(b'broad-dns-before-network')
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.settimeout(1.5)
sock.sendto(bytes.fromhex(query_hex), ('127.0.0.1', int(port)))
reply, _ = sock.recvfrom(512)
if reply != bytes.fromhex(reply_hex): sys.exit(41)
print('dns-fixture-reply-observed', flush=True)
"#
    } else {
        r#"
import errno, socket, sys
path, port, query_hex = sys.argv[1:]
with open(path, 'wb') as marker: marker.write(b'closed-dns-before-denial')
query = bytes.fromhex(query_hex)
try:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
except OSError as error:
    if error.errno != errno.EPERM: sys.exit(42)
    print('dns-socket-denied', flush=True)
else:
    try: sock.sendto(query, ('127.0.0.1', int(port)))
    except OSError as error:
        if error.errno != errno.EPERM: sys.exit(43)
        print('dns-send-denied', flush=True)
    else: sys.exit(44)
"#
    };
    let mut argv = vec![
        OsString::from("/usr/bin/python3"),
        OsString::from("-c"),
        OsString::from(script),
        marker.to_owned().into_os_string(),
        OsString::from(port.to_string()),
        OsString::from(hex(query)),
    ];
    if mode == "broad" {
        argv.push(OsString::from(hex(reply)));
    }
    let command = none::command(&sealed, fixture, argv);
    let mut child = command
        .spawn_gated_with_containment_with_io(
            &fixture.area,
            b"",
            none::limits(),
            none::containment(fixture),
        )
        .expect("stopped network qualification child");
    assert!(!child.was_released());
    child
        .release()
        .expect("release network qualification child");
    qualification::finish_child(child, Duration::from_secs(4))
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
