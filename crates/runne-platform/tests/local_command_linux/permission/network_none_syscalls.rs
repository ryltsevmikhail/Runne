use super::network_none::support as none;
use super::network_qualification_support::{self as qualification, Aligned, Kind, Probe};
use runne_application::permission_modes::NetworkScope;
use std::ffi::OsString;
use std::fs::File;
use std::time::Duration;

#[test]
fn network_none_denies_ipv6_stream_and_datagram_socket_syscalls() {
    eprintln!("RUN: network_none_denies_ipv6_stream_and_datagram_socket_syscalls");
    let fixture = qualification::fixture(NetworkScope::None);
    let marker = fixture.workspace.0.join("ipv6-socket-probe");
    let socket_number = libc::SYS_socket;
    let family = libc::AF_INET6;
    let stream = libc::SOCK_STREAM;
    let datagram = libc::SOCK_DGRAM;
    let (stream_result, stream_errno) =
        qualification::socket_baseline(socket_number, family, stream);
    let (datagram_result, datagram_errno) =
        qualification::socket_baseline(socket_number, family, datagram);
    eprintln!("BASELINE ipv6_stream result={stream_result} errno={stream_errno}");
    eprintln!("BASELINE ipv6_datagram result={datagram_result} errno={datagram_errno}");
    assert!(stream_result >= 0, "parent IPv6 stream baseline was denied");
    assert!(
        datagram_result >= 0,
        "parent IPv6 datagram baseline was denied"
    );
    let executable = File::open("/usr/bin/python3").expect("Python executable");
    let sealed =
        runne_platform::local_command_linux::SealedExecutableSnapshot::from_held_file(&executable)
            .expect("sealed Python");
    let script = r#"
import ctypes, errno, os, sys
path, number, family, stream, datagram, stream_result, stream_errno, datagram_result, datagram_errno = sys.argv[1:]
open(path, 'wb').write(b'ipv6-probe-before-denial')
libc = ctypes.CDLL(None, use_errno=True)
libc.syscall.restype = ctypes.c_long
for name, kind, parent_result, parent_errno in [
    ('ipv6_stream', int(stream), int(stream_result), int(stream_errno)),
    ('ipv6_datagram', int(datagram), int(datagram_result), int(datagram_errno)),
]:
    ctypes.set_errno(0)
    result = libc.syscall(int(number), int(family), kind, 0)
    code = ctypes.get_errno()
    print(f'{name}:parent={parent_result}/{parent_errno};child={result}/{code}', flush=True)
    if result != -1 or code != errno.EPERM:
        if result >= 0: os.close(result)
        sys.exit(41)
"#;
    let argv = vec![
        OsString::from("/usr/bin/python3"),
        OsString::from("-c"),
        OsString::from(script),
        marker.clone().into_os_string(),
        OsString::from(socket_number.to_string()),
        OsString::from(family.to_string()),
        OsString::from(stream.to_string()),
        OsString::from(datagram.to_string()),
        OsString::from(stream_result.to_string()),
        OsString::from(stream_errno.to_string()),
        OsString::from(datagram_result.to_string()),
        OsString::from(datagram_errno.to_string()),
    ];
    run_child(
        &fixture,
        &sealed,
        argv,
        &marker,
        b"ipv6-probe-before-denial",
        2,
    );
    fixture.area.prove_empty().unwrap().revalidate().unwrap();
    fixture.area.remove();
}

#[test]
fn network_none_denies_remaining_socket_and_io_uring_syscalls_after_go() {
    eprintln!("RUN: network_none_denies_remaining_socket_and_io_uring_syscalls_after_go");
    let fixture = qualification::fixture(NetworkScope::None);
    let marker = fixture.workspace.0.join("remaining-network-probes");
    macro_rules! probe {
        ($name:literal, $number:expr, $kind:expr) => {
            Probe {
                name: $name,
                number: $number,
                kind: $kind,
            }
        };
    }
    let probes = [
        probe!("recvfrom", libc::SYS_recvfrom, Kind::Recvfrom),
        probe!("sendmsg", libc::SYS_sendmsg, Kind::Message),
        probe!("recvmsg", libc::SYS_recvmsg, Kind::Message),
        probe!("sendmmsg", libc::SYS_sendmmsg, Kind::MultiMessage),
        probe!("recvmmsg", libc::SYS_recvmmsg, Kind::MultiMessageTimed),
        probe!("accept4", libc::SYS_accept4, Kind::Accept4),
        probe!("getsockname", libc::SYS_getsockname, Kind::Name),
        probe!("getpeername", libc::SYS_getpeername, Kind::Name),
        probe!("shutdown", libc::SYS_shutdown, Kind::Shutdown),
        probe!("setsockopt", libc::SYS_setsockopt, Kind::SetOption),
        probe!("getsockopt", libc::SYS_getsockopt, Kind::GetOption),
        probe!("io_uring_setup", libc::SYS_io_uring_setup, Kind::UringSetup),
        probe!("io_uring_enter", libc::SYS_io_uring_enter, Kind::UringEnter),
        probe!(
            "io_uring_register",
            libc::SYS_io_uring_register,
            Kind::UringRegister
        ),
    ];
    let mut memory = Aligned([0; 512]);
    let mut option = 0_i32;
    let mut option_len = std::mem::size_of::<i32>() as libc::socklen_t;
    let mut address_len = 128_u32;
    let mut baselines = Vec::new();
    for probe in probes {
        let (result, errno) = qualification::parent_baseline(
            probe,
            &mut memory,
            &mut option,
            &mut option_len,
            &mut address_len,
        );
        eprintln!("BASELINE {} result={result} errno={errno}", probe.name);
        match probe.kind {
            Kind::UringSetup => {
                if result >= 0 {
                    unsafe { libc::close(result as libc::c_int) };
                } else if errno == libc::EPERM {
                    eprintln!(
                        "BOUNDARY io_uring_setup: parent already returned EPERM; child EPERM is not newly attributed"
                    );
                }
            }
            _ => assert_eq!(errno, libc::EBADF, "parent baseline for {}", probe.name),
        }
        baselines.push((probe, result, errno));
    }
    let executable = File::open("/usr/bin/python3").expect("Python executable");
    let sealed =
        runne_platform::local_command_linux::SealedExecutableSnapshot::from_held_file(&executable)
            .expect("sealed Python");
    let script = r#"
import ctypes, errno, os, sys
path, *values = sys.argv[1:]
open(path, 'wb').write(b'network-syscalls-before-denial')
libc = ctypes.CDLL(None, use_errno=True)
libc.syscall.restype = ctypes.c_long
data = ctypes.create_string_buffer(16)
message = ctypes.create_string_buffer(256)
address = ctypes.create_string_buffer(128)
address_len = ctypes.c_uint(128)
option = ctypes.c_int(0)
option_len = ctypes.c_uint(ctypes.sizeof(option))
params = ctypes.create_string_buffer(128)
buffer = ctypes.create_string_buffer(8)
class IOVec(ctypes.Structure):
    _fields_ = [('iov_base', ctypes.c_void_p), ('iov_len', ctypes.c_size_t)]
iovec = IOVec(ctypes.addressof(buffer), ctypes.sizeof(buffer))
calls = {
    'recvfrom': (-1, data, 1, 0, address, ctypes.byref(address_len)),
    'sendmsg': (-1, message, 0), 'recvmsg': (-1, message, 0),
    'sendmmsg': (-1, message, 1, 0), 'recvmmsg': (-1, message, 1, 0, None),
    'accept4': (-1, address, ctypes.byref(address_len), 0),
    'getsockname': (-1, address, ctypes.byref(address_len)),
    'getpeername': (-1, address, ctypes.byref(address_len)),
    'shutdown': (-1, 2),
    'setsockopt': (-1, 1, 8, ctypes.byref(option), ctypes.sizeof(option)),
    'getsockopt': (-1, 1, 8, ctypes.byref(option), ctypes.byref(option_len)),
    'io_uring_setup': (1, params), 'io_uring_enter': (-1, 0, 0, 0, None, 0),
    'io_uring_register': (2147483647, 0, ctypes.byref(iovec), 1),
}
for offset in range(0, len(values), 4):
    name, number, parent_result, parent_errno = values[offset:offset + 4]
    ctypes.set_errno(0)
    result = libc.syscall(int(number), *calls[name])
    code = ctypes.get_errno()
    print(f'{name}:parent={parent_result}/{parent_errno};child={result}/{code}', flush=True)
    if result != -1 or code != errno.EPERM:
        if name == 'io_uring_setup' and result >= 0: os.close(result)
        sys.exit(42)
"#;
    let mut argv = vec![
        OsString::from("/usr/bin/python3"),
        OsString::from("-c"),
        OsString::from(script),
        marker.clone().into_os_string(),
    ];
    for (probe, result, errno) in &baselines {
        argv.extend([
            OsString::from(probe.name),
            OsString::from(probe.number.to_string()),
            OsString::from(result.to_string()),
            OsString::from(errno.to_string()),
        ]);
    }
    run_child(
        &fixture,
        &sealed,
        argv,
        &marker,
        b"network-syscalls-before-denial",
        probes.len(),
    );
    fixture.area.prove_empty().unwrap().revalidate().unwrap();
    fixture.area.remove();
}

fn run_child(
    fixture: &none::Fixture,
    executable: &runne_platform::local_command_linux::SealedExecutableSnapshot,
    argv: Vec<OsString>,
    marker: &std::path::Path,
    marker_bytes: &[u8],
    expected_lines: usize,
) {
    let command = none::command(executable, fixture, argv);
    let mut child = command
        .spawn_gated_with_containment_with_io(
            &fixture.area,
            b"",
            none::limits(),
            none::containment(fixture),
        )
        .expect("stopped closed-network child");
    assert!(!child.was_released());
    child.release().expect("release closed-network child");
    let (code, stdout, stderr) = qualification::finish_child(child, Duration::from_secs(4));
    assert_eq!(code, 0, "child network probe failed: {stderr:?} {stdout:?}");
    assert!(stderr.is_empty(), "unexpected child stderr: {stderr:?}");
    assert_eq!(std::fs::read(marker).expect("child marker"), marker_bytes);
    let output = std::str::from_utf8(&stdout).expect("UTF-8 probe output");
    assert_eq!(output.lines().count(), expected_lines);
    assert!(output.lines().all(|line| line.contains(";child=-1/1")));
}
