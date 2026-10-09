use super::support::{command, containment, fixture, limits, python};
use std::ffi::OsString;
use std::time::{Duration, Instant};

#[test]
fn forked_descendant_inherits_network_none_for_sockets_unix_and_alt_syscalls() {
    eprintln!("RUN: forked_descendant_inherits_network_none_for_sockets_unix_and_alt_syscalls");
    let Some(fixture) = fixture() else {
        return;
    };
    let marker = fixture.workspace.0.join("descendant-before-network-denial");
    let script = r#"
import ctypes, errno, os, socket, sys
pid = os.fork()
if pid == 0:
    with open(sys.argv[1], 'wb') as output: output.write(b'descendant-write')
    for family, kind in [
        (socket.AF_INET, socket.SOCK_STREAM),
        (socket.AF_INET, socket.SOCK_DGRAM),
        (socket.AF_UNIX, socket.SOCK_STREAM),
        (socket.AF_NETLINK, socket.SOCK_RAW),
    ]:
        try: socket.socket(family, kind)
        except OSError as error:
            if error.errno != errno.EPERM: os._exit(45)
        else: os._exit(41)
    try: socket.socketpair()
    except OSError as error:
        if error.errno != errno.EPERM: os._exit(46)
    else: os._exit(42)
    # Resolver errors alone do not prove a network send was attempted. The
    # socket() calls and direct syscall below are the actual kernel evidence.
    try: socket.getaddrinfo('closed-descendant.invalid', 80, type=socket.SOCK_STREAM)
    except OSError: pass
    else: os._exit(43)
    libc = ctypes.CDLL(None, use_errno=True)
    data = ctypes.create_string_buffer(b'x')
    libc.sendto.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_size_t,
                            ctypes.c_int, ctypes.c_void_p, ctypes.c_uint]
    ctypes.set_errno(0)
    if libc.sendto(-1, data, 1, 0, None, 0) != -1 or ctypes.get_errno() != errno.EPERM:
        os._exit(44)
    os._exit(0)
_, status = os.waitpid(pid, 0)
sys.exit(os.waitstatus_to_exitcode(status))
"#;
    let (_python_file, sealed) = python();
    let command = command(
        &sealed,
        &fixture,
        vec![
            OsString::from("/usr/bin/python3"),
            OsString::from("-c"),
            OsString::from(script),
            marker.clone().into_os_string(),
        ],
    );
    let mut child = command
        .spawn_gated_with_containment_with_io(&fixture.area, b"", limits(), containment(&fixture))
        .expect("stopped closed-network parent");
    child.release().expect("release parent");
    let code = child
        .wait(Duration::from_secs(8))
        .expect("parent and descendant exit");
    assert_eq!(code, 0, "a descendant used an alternate network path");
    assert_eq!(std::fs::read(marker).unwrap(), b"descendant-write");
    fixture.area.prove_empty().unwrap().revalidate().unwrap();
    fixture.area.remove();
}

#[test]
fn write_before_network_denial_then_cancel_kills_and_reaps_descendants() {
    eprintln!("RUN: write_before_network_denial_then_cancel_kills_and_reaps_descendants");
    let Some(fixture) = fixture() else {
        return;
    };
    let before = fixture.workspace.0.join("partial-write-before-denial");
    let denied = fixture.workspace.0.join("descendant-network-denied");
    let script = r#"
import errno, os, socket, sys, time
with open(sys.argv[1], 'wb') as output: output.write(b'partial-effect')
pid = os.fork()
if pid == 0:
    try: socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    except OSError as error:
        if error.errno != errno.EPERM: os._exit(41)
    else: os._exit(42)
    with open(sys.argv[2], 'wb') as output: output.write(b'network-denied')
while True: time.sleep(10)
"#;
    let (_python_file, sealed) = python();
    let command = command(
        &sealed,
        &fixture,
        vec![
            OsString::from("/usr/bin/python3"),
            OsString::from("-c"),
            OsString::from(script),
            before.clone().into_os_string(),
            denied.clone().into_os_string(),
        ],
    );
    let mut child = command
        .spawn_gated_with_containment_with_io(&fixture.area, b"", limits(), containment(&fixture))
        .expect("stopped cancellation test child");
    child.release().expect("release cancellation test child");
    wait_for_file(&denied);
    assert_eq!(std::fs::read(before).unwrap(), b"partial-effect");
    assert_eq!(std::fs::read(&denied).unwrap(), b"network-denied");
    child
        .cancel(Duration::from_millis(20))
        .expect("kill and reap leader and descendant");
    fixture.area.prove_empty().unwrap().revalidate().unwrap();
    fixture.area.remove();
}

fn wait_for_file(path: &std::path::Path) {
    let deadline = Instant::now() + Duration::from_secs(5);
    while !path.exists() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(path.exists(), "descendant never recorded network denial");
}
