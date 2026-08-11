use std::fs;
use std::path::Path;

#[test]
fn audited_shim_exposes_only_safe_windows_handle_primitives() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let lib = fs::read_to_string(root.join("src/lib.rs")).unwrap();
    let identity = fs::read_to_string(root.join("src/identity.rs")).unwrap();
    let duplicate = fs::read_to_string(root.join("src/duplicate.rs")).unwrap();
    let relative = fs::read_to_string(root.join("src/relative.rs")).unwrap();

    assert!(lib.contains("pub use duplicate::{ExactTargetProcess, RemoteHandleLease}"));
    assert!(
        lib.contains("pub use identity::{DirectoryHandle, DirectoryIdentity, NativeHandleError}")
    );
    assert!(identity.contains("pub struct DirectoryHandle"));
    assert!(duplicate.contains("pub struct RemoteHandleLease"));
    assert!(identity.contains("GetFileInformationByHandleEx"));
    assert!(identity.contains("FileIdInfo"));
    assert!(identity.contains("FILE_FLAG_OPEN_REPARSE_POINT"));
    assert!(relative.contains("FILE_OPEN_REPARSE_POINT"));
    assert!(relative.contains("NtCreateFile"));
    assert!(duplicate.contains("DuplicateHandle"));
    assert!(duplicate.contains("DUPLICATE_CLOSE_SOURCE"));
    assert!(identity.contains("HANDLE_FLAG_INHERIT"));
    assert!(duplicate.contains("impl Drop for RemoteHandleLease"));
    assert!(duplicate.contains("GetProcessId"));
    assert!(!lib.contains("pub fn raw_handle"));
}
