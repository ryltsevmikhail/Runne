use super::support;
use runne_application::permission_modes::{FilesystemPermission, NetworkScope};
use runne_application::project_trust::ManagedEffectClass;
use std::fs;
use std::io::Read;
use std::net::TcpListener;

#[test]
fn create_deny_keeps_existing_write_truncate_and_broad_network() {
    eprintln!("RUN: create_deny_keeps_existing_write_truncate_and_broad_network");
    let Some(fixture) = support::fixture(
        NetworkScope::BroadSameUser,
        [FilesystemPermission::Read, FilesystemPermission::Write],
        Some(ManagedEffectClass::FsCreate),
    ) else {
        return;
    };
    let listener = TcpListener::bind(("127.0.0.1", 0)).expect("loopback listener");
    let port = listener.local_addr().unwrap().port().to_string();
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let Ok((mut stream, _)) = listener.accept() else {
            return;
        };
        let mut bytes = [0; 32];
        if let Ok(size) = stream.read(&mut bytes) {
            let _ = tx.send(bytes[..size].to_vec());
        }
    });
    let existing = fixture.workspace.0.join("existing");
    let new_file = fixture.workspace.0.join("new-file");
    let new_dir = fixture.workspace.0.join("new-dir");
    let symlink = fixture.workspace.0.join("new-link");
    let hardlink = fixture.workspace.0.join("new-hardlink");
    let renamed = fixture.workspace.0.join("renamed");
    fs::write(&existing, b"truncate-this").unwrap();
    let code = r#"
import ctypes, errno, os, socket, sys
existing, newfile, newdir, symlink, hardlink, renamed, port = sys.argv[1:]
fd = os.open(existing, os.O_WRONLY | os.O_TRUNC)
os.write(fd, b'write-ok')
os.ftruncate(fd, 4)
os.close(fd)
assert open(existing, 'rb').read() == b'writ'
def denied(call):
    try: call()
    except OSError as error:
        assert error.errno in (errno.EPERM, errno.EACCES), error.errno
        return
    raise AssertionError('create unexpectedly succeeded')
denied(lambda: os.open(newfile, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600))
denied(lambda: os.mkdir(newdir))
denied(lambda: os.symlink(existing, symlink))
denied(lambda: os.link(existing, hardlink))
denied(lambda: os.rename(existing, renamed))
with socket.create_connection(('127.0.0.1', int(port)), timeout=2) as stream:
    stream.sendall(b'broad-ok')
"#;
    let args = [
        existing.to_str().unwrap(),
        new_file.to_str().unwrap(),
        new_dir.to_str().unwrap(),
        symlink.to_str().unwrap(),
        hardlink.to_str().unwrap(),
        renamed.to_str().unwrap(),
        port.as_str(),
    ];
    assert_eq!(support::run_python(&fixture, code, &args), 0);
    assert_eq!(
        rx.recv_timeout(std::time::Duration::from_secs(2)).unwrap(),
        b"broad-ok"
    );
    assert_eq!(fs::read(existing).unwrap(), b"writ");
    fixture.cleanup();
}
