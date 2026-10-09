#[path = "fs_partial_create.rs"]
mod create;
#[path = "fs_partial_inherited.rs"]
mod inherited;
#[path = "fs_partial_read.rs"]
mod read;
#[path = "fs_partial_rename.rs"]
mod rename;
#[path = "fs_partial_support.rs"]
mod support;
#[path = "fs_partial_write.rs"]
mod write;

use runne_application::permission_modes::{FilesystemPermission, NetworkScope};
use runne_application::project_trust::ManagedEffectClass;
use std::fs;

#[test]
fn fs_delete_deny_preserves_read_create_write_and_denies_unlink_and_rename() {
    eprintln!("RUN: fs_delete_deny_preserves_read_create_write_and_denies_unlink_and_rename");
    let Some(fixture) = support::fixture(
        NetworkScope::None,
        [
            FilesystemPermission::Read,
            FilesystemPermission::Create,
            FilesystemPermission::Write,
        ],
        Some(ManagedEffectClass::FsDelete),
    ) else {
        return;
    };
    let inside = fixture.workspace.0.join("inside");
    let outside = fixture.workspace.0.parent().unwrap().join(format!(
        "{}-outside",
        inside.file_name().unwrap().to_string_lossy()
    ));
    let hardlink = fixture.workspace.0.join("hardlink");
    let rename_from = fixture.workspace.0.join("rename-from");
    let rename_to = fixture.workspace.0.join("rename-to");
    let exchange_a = fixture.workspace.0.join("exchange-a");
    let exchange_b = fixture.workspace.0.join("exchange-b");
    let remove_dir = fixture.workspace.0.join("remove-dir");
    fs::write(&inside, b"inside-seed").unwrap();
    fs::write(&outside, b"outside-seed").unwrap();
    fs::write(&rename_from, b"rename-source").unwrap();
    fs::write(&exchange_a, b"a").unwrap();
    fs::write(&exchange_b, b"b").unwrap();
    fs::create_dir(&remove_dir).unwrap();
    let code = r#"
import ctypes, errno, os, sys
inside, outside, hardlink, src, dst, a, b, empty, protected = sys.argv[1:10]
assert open(inside, 'rb').read() == b'inside-seed'
assert open(outside, 'rb').read() == b'outside-seed'
open(inside, 'ab').write(b'-write-ok')
open(outside, 'ab').write(b'-write-ok')
open(inside + '-new', 'wb').write(b'create-ok')
open(outside + '-new', 'wb').write(b'outside-create-ok')
os.link(inside, hardlink)
assert os.stat(hardlink).st_ino == os.stat(inside).st_ino
libc = ctypes.CDLL(None, use_errno=True)
libc.syscall.restype = ctypes.c_long
def denied(call):
    try:
        result = call()
    except OSError as error:
        assert error.errno in (errno.EPERM, errno.EACCES), error.errno
        return
    if result == 0:
        raise AssertionError('delete or rename unexpectedly succeeded')
    assert ctypes.get_errno() in (errno.EPERM, errno.EACCES), ctypes.get_errno()
denied(lambda: os.unlink(inside))
denied(lambda: libc.syscall(ctypes.c_long(int(sys.argv[10])), ctypes.c_char_p(os.fsencode(inside))))
denied(lambda: libc.syscall(ctypes.c_long(int(sys.argv[11])), ctypes.c_long(-100), ctypes.c_char_p(os.fsencode(inside)), ctypes.c_long(0)))
denied(lambda: libc.syscall(ctypes.c_long(int(sys.argv[12])), ctypes.c_char_p(os.fsencode(empty))))
denied(lambda: os.rename(src, dst))
denied(lambda: libc.syscall(ctypes.c_long(int(sys.argv[13])), ctypes.c_char_p(os.fsencode(src)), ctypes.c_char_p(os.fsencode(dst))))
denied(lambda: libc.syscall(ctypes.c_long(int(sys.argv[14])), ctypes.c_long(-100), ctypes.c_char_p(os.fsencode(src)), ctypes.c_long(-100), ctypes.c_char_p(os.fsencode(dst))))
denied(lambda: libc.syscall(ctypes.c_long(int(sys.argv[15])), ctypes.c_long(-100), ctypes.c_char_p(os.fsencode(a)), ctypes.c_long(-100), ctypes.c_char_p(os.fsencode(b)), ctypes.c_long(2)))
try:
    open(os.path.join(protected, 'protected-secret'), 'rb').read()
    raise AssertionError('protected overlay exposed a protected file')
except OSError:
    pass
"#;
    let args = [
        inside.to_str().unwrap().to_owned(),
        outside.to_str().unwrap().to_owned(),
        hardlink.to_str().unwrap().to_owned(),
        rename_from.to_str().unwrap().to_owned(),
        rename_to.to_str().unwrap().to_owned(),
        exchange_a.to_str().unwrap().to_owned(),
        exchange_b.to_str().unwrap().to_owned(),
        remove_dir.to_str().unwrap().to_owned(),
        fixture.protected_dir.path().to_str().unwrap().to_owned(),
    ];
    let numbers = [
        libc::SYS_unlink,
        libc::SYS_unlinkat,
        libc::SYS_rmdir,
        libc::SYS_rename,
        libc::SYS_renameat,
        libc::SYS_renameat2,
    ];
    let numeric_args = numbers.iter().map(|n| n.to_string()).collect::<Vec<_>>();
    let mut all = args.iter().map(String::as_str).collect::<Vec<_>>();
    all.extend(numeric_args.iter().map(String::as_str));
    let code = support::run_python(&fixture, code, &all);
    assert_eq!(
        code, 0,
        "partial profile must allow only its selected classes"
    );
    assert_eq!(fs::read(&inside).unwrap(), b"inside-seed-write-ok");
    assert_eq!(fs::read(&outside).unwrap(), b"outside-seed-write-ok");
    assert_eq!(
        fs::read(format!("{}-new", outside.display())).unwrap(),
        b"outside-create-ok"
    );
    assert_eq!(fs::read(hardlink).unwrap(), b"inside-seed-write-ok");
    assert!(!rename_to.exists());
    assert_eq!(fs::read(exchange_a).unwrap(), b"a");
    assert_eq!(fs::read(exchange_b).unwrap(), b"b");
    fixture.cleanup();
    let _ = fs::remove_file(&outside);
    let _ = fs::remove_file(format!("{}-new", outside.display()));
}
