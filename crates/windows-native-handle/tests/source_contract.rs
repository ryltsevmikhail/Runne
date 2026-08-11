use std::fs;
use std::path::Path;

#[test]
fn audited_shim_exposes_only_safe_windows_handle_primitives() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let lib = fs::read_to_string(root.join("src/lib.rs")).unwrap();
    let identity = fs::read_to_string(root.join("src/identity.rs")).unwrap();
    let duplicate = fs::read_to_string(root.join("src/duplicate.rs")).unwrap();
    let path = fs::read_to_string(root.join("src/path.rs")).unwrap();
    let receiver = fs::read_to_string(root.join("src/receiver.rs")).unwrap();
    let relative = fs::read_to_string(root.join("src/relative.rs")).unwrap();

    assert!(lib.contains(
        "pub use duplicate::{ExactTargetProcess, LauncherProcessBinding, RemoteHandleLease}"
    ));
    assert!(
        lib.contains("pub use identity::{DirectoryHandle, DirectoryIdentity, NativeHandleError}")
    );
    assert!(lib.contains("AcceptedDirectory, HandleOfferAck, ProtectedHandleOffer"));
    assert!(identity.contains("pub struct DirectoryHandle"));
    assert!(duplicate.contains("pub struct RemoteHandleLease"));
    assert!(identity.contains("GetFileInformationByHandleEx"));
    assert!(identity.contains("FileIdInfo"));
    assert!(identity.contains("FILE_FLAG_OPEN_REPARSE_POINT"));
    assert!(relative.contains("FILE_OPEN_REPARSE_POINT"));
    assert!(identity.contains("verify_directory"));
    assert!(identity.contains("unsupported_file_id"));
    assert!(path.contains("reject_raw_windows_grammar"));
    assert!(path.contains("is_ascii_letter"));
    assert!(!path.contains("Prefix::UNC"));
    assert!(relative.contains("NtCreateFile"));
    assert!(duplicate.contains("DuplicateHandle"));
    assert!(duplicate.contains("DUPLICATE_CLOSE_SOURCE"));
    assert!(identity.contains("HANDLE_FLAG_INHERIT"));
    assert!(duplicate.contains("impl Drop for RemoteHandleLease"));
    assert!(duplicate.contains("let remote = self.remote.take()"));
    assert!(duplicate.contains("from_launcher_child"));
    assert!(duplicate.contains("AsRawHandle"));
    assert!(!duplicate.contains("OpenProcess"));
    assert!(receiver.contains("clone_received_and_verify"));
    assert!(receiver.contains("into_protected_bytes"));
    assert!(receiver.contains("from_protected_bytes"));
    assert!(receiver.contains("ReceiverDisposition::Ack"));
    assert!(receiver.contains("ReceiverDisposition::Nack"));
    assert!(receiver.contains("ReceiverDisposition::Expired"));
    assert!(receiver.contains("BTreeMap"));
    assert!(receiver.contains("pending.remove"));
    assert!(receiver.contains("duplicate_local"));
    assert!(!lib.contains("pub fn raw_handle"));
}
