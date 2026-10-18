use super::support::{command, containment, fd_of, fixture, limits, make_inheritable, python};
use std::ffi::OsString;
use std::net::{TcpListener, TcpStream};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::time::Duration;

#[test]
fn closed_network_none_closes_inherited_sockets_and_denies_network_syscalls_after_write() {
    eprintln!(
        "RUN: closed_network_none_closes_inherited_sockets_and_denies_network_syscalls_after_write"
    );
    let Some(fixture) = fixture() else {
        return;
    };
    let listener = TcpListener::bind(("127.0.0.1", 0)).expect("local listener");
    let client = TcpStream::connect(listener.local_addr().unwrap()).expect("local connection");
    let (accepted, _) = listener.accept().expect("accepted local connection");
    let mut pair = [-1; 2];
    assert_eq!(
        unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, pair.as_mut_ptr()) },
        0
    );
    let pair = unsafe { [OwnedFd::from_raw_fd(pair[0]), OwnedFd::from_raw_fd(pair[1])] };
    let inherited = [
        fd_of(&listener),
        fd_of(&client),
        fd_of(&accepted),
        pair[0].as_raw_fd(),
        pair[1].as_raw_fd(),
    ];
    for fd in inherited {
        make_inheritable(fd);
    }

    let marker = fixture.workspace.0.join("written-before-network-denial");
    let script = r#"
import ctypes, errno, os, socket, sys
path, *fds = sys.argv[1:]
fds = [int(fd) for fd in fds]
with open(path, 'wb') as marker: marker.write(b'write-before-denial')
for fd in fds:
    try: os.fstat(fd)
    except OSError as error:
        if error.errno != errno.EBADF: sys.exit(40)
    else: sys.exit(41)
libc = ctypes.CDLL(None, use_errno=True)
data = ctypes.create_string_buffer(b'x')
libc.sendto.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_size_t,
                        ctypes.c_int, ctypes.c_void_p, ctypes.c_uint]
libc.connect.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_uint]
libc.bind.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_uint]
libc.listen.argtypes = [ctypes.c_int, ctypes.c_int]
libc.accept.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_void_p]
for name, args in [
    ('sendto', (fds[1], data, 1, 0, None, 0)),
    ('connect', (fds[1], None, 0)),
    ('bind', (fds[0], None, 0)),
    ('listen', (fds[0], 1)),
    ('accept', (fds[0], None, None)),
]:
    ctypes.set_errno(0)
    if getattr(libc, name)(*args) != -1 or ctypes.get_errno() != errno.EPERM: sys.exit(42)
for family, kind in [
    (socket.AF_INET, socket.SOCK_STREAM),
    (socket.AF_INET, socket.SOCK_DGRAM),
    (socket.AF_UNIX, socket.SOCK_STREAM),
    (socket.AF_NETLINK, socket.SOCK_RAW),
]:
    try: socket.socket(family, kind)
    except OSError as error:
        if error.errno != errno.EPERM: sys.exit(46)
    else: sys.exit(43)
try: socket.socketpair()
except OSError as error:
    if error.errno != errno.EPERM: sys.exit(47)
else: sys.exit(44)
# Resolver failure is indirect coverage only; the explicit socket syscall
# checks above establish kernel network denial without depending on DNS setup.
try: socket.getaddrinfo('closed-coverage.invalid', 80, type=socket.SOCK_STREAM)
except OSError: pass
else: sys.exit(45)
"#;
    let (_python_file, sealed) = python();
    let command = command(
        &sealed,
        &fixture,
        std::iter::once(OsString::from("/usr/bin/python3"))
            .chain([
                OsString::from("-c"),
                OsString::from(script),
                marker.clone().into_os_string(),
            ])
            .chain(inherited.map(|fd| OsString::from(fd.to_string())))
            .collect(),
    );
    let mut child = command
        .spawn_gated_with_containment_with_io(&fixture.area, b"", limits(), containment(&fixture))
        .expect("stopped closed-network child");
    child.release().expect("release closed-network child");
    let code = child
        .wait(Duration::from_secs(8))
        .expect("closed-network child exit");
    assert_eq!(
        code, 0,
        "inherited or newly created network effects escaped"
    );
    assert_eq!(std::fs::read(marker).unwrap(), b"write-before-denial");
    fixture.area.prove_empty().unwrap().revalidate().unwrap();
    fixture.area.remove();
}
