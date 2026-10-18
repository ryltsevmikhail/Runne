use super::support;
use runne_application::permission_modes::{FilesystemPermission, NetworkScope};
use std::fs;

#[test]
fn create_delete_write_enable_link_rename_replace_and_exchange() {
    eprintln!("RUN: create_delete_write_enable_link_rename_replace_and_exchange");
    let Some(fixture) = support::fixture(
        NetworkScope::None,
        [
            FilesystemPermission::Read,
            FilesystemPermission::Create,
            FilesystemPermission::Write,
            FilesystemPermission::Delete,
        ],
        None,
    ) else {
        return;
    };
    let root = &fixture.workspace.0;
    let source = root.join("source");
    let target = root.join("target");
    let replacement = root.join("replacement");
    let hardlink = root.join("hardlink");
    let left = root.join("left");
    let right = root.join("right");
    fs::write(&source, b"source").unwrap();
    fs::write(&target, b"old-target").unwrap();
    fs::write(&replacement, b"replacement").unwrap();
    fs::write(&left, b"left").unwrap();
    fs::write(&right, b"right").unwrap();
    let code = r#"
import ctypes, os, sys
source, target, replacement, hardlink, left, right, nr = sys.argv[1:]
os.link(source, hardlink)
os.rename(source, target)
os.replace(replacement, source)
libc = ctypes.CDLL(None, use_errno=True)
libc.syscall.restype = ctypes.c_long
result = libc.syscall(ctypes.c_long(int(nr)), ctypes.c_long(-100), ctypes.c_char_p(os.fsencode(left)), ctypes.c_long(-100), ctypes.c_char_p(os.fsencode(right)), ctypes.c_long(2))
assert result == 0, ctypes.get_errno()
"#;
    let number = libc::SYS_renameat2.to_string();
    let args = [
        source.to_str().unwrap(),
        target.to_str().unwrap(),
        replacement.to_str().unwrap(),
        hardlink.to_str().unwrap(),
        left.to_str().unwrap(),
        right.to_str().unwrap(),
        number.as_str(),
    ];
    assert_eq!(support::run_python(&fixture, code, &args), 0);
    assert_eq!(fs::read(&target).unwrap(), b"source");
    assert_eq!(fs::read(&hardlink).unwrap(), b"source");
    assert_eq!(fs::read(&source).unwrap(), b"replacement");
    assert_eq!(fs::read(&left).unwrap(), b"right");
    assert_eq!(fs::read(&right).unwrap(), b"left");
    fixture.cleanup();
}
