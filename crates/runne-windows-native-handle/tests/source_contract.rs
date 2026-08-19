use std::fs;
use std::path::Path;

#[test]
fn audited_shim_keeps_v2_protocol_and_native_ownership_bounded() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let lib = fs::read_to_string(root.join("src/lib.rs")).unwrap();
    let clock = fs::read_to_string(root.join("src/clock.rs")).unwrap();
    let duplicate = fs::read_to_string(root.join("src/duplicate.rs")).unwrap();
    let identity = fs::read_to_string(root.join("src/identity.rs")).unwrap();
    let model = fs::read_to_string(root.join("src/model.rs")).unwrap();
    let path = fs::read_to_string(root.join("src/path.rs")).unwrap();
    let receiver = fs::read_to_string(root.join("src/receiver.rs")).unwrap();
    let regular_file = fs::read_to_string(root.join("src/regular_file.rs")).unwrap();
    let relative = fs::read_to_string(root.join("src/relative.rs")).unwrap();
    let wire = fs::read_to_string(root.join("src/wire.rs")).unwrap();

    assert!(lib.contains(
        "pub use wire::{HandleAckReady, HandleFinalize, HandleNack, ProtectedHandleOffer}"
    ));
    assert!(lib.contains("#[cfg(windows)]"));
    assert!(wire.contains("GHO2"));
    assert!(wire.contains("GHA2"));
    assert!(wire.contains("GHF2"));
    assert!(wire.contains("GHN2"));
    assert!(wire.contains("const OFFER_BYTES: usize = 104"));
    assert!(wire.contains("const CONTROL_BYTES: usize = 64"));
    assert!(wire.contains("runne.root-handle-offer.v2"));
    assert!(clock.contains("previous.max(anchored).max(sample.wall_millis)"));
    assert!(clock.contains("ClockRegression"));
    assert!(clock.contains("MAX_OFFER_MILLIS"));
    assert!(model.contains("const MAX_RECORDS: usize = 64"));
    assert!(model.contains("Entry::Terminal"));
    assert!(model.contains("ControlAction::Commit"));
    assert!(receiver.contains("CommittedDirectory"));
    assert!(receiver.contains("AckReady"));
    assert!(receiver.contains("fn close"));
    assert!(duplicate.contains("pub struct OfferedRemoteHandleLease"));
    assert!(duplicate.contains("acknowledge_ready"));
    assert!(duplicate.contains("let remote = self.remote.take()"));
    assert!(duplicate.contains("DUPLICATE_CLOSE_SOURCE"));
    assert!(identity.contains("GetFileInformationByHandleEx"));
    assert!(identity.contains("FILE_FLAG_OPEN_REPARSE_POINT"));
    assert!(relative.contains("NtCreateFile"));
    assert!(path.contains("reject_raw_windows_grammar"));
    assert!(!wire.contains("GHR1"));
    assert!(!lib.contains("HandleOfferAck"));
    assert!(!lib.contains("AcceptedDirectory"));
    assert!(!receiver.contains("clone_received_and_verify"));
    assert!(!lib.contains("pub fn raw_handle"));
    assert!(lib.contains("mod regular_file"));
    assert!(regular_file.contains("FILE_ID_INFO"));
    assert!(regular_file.contains("FileAttributeTagInfo"));
    assert!(regular_file.contains("FileStandardInfo"));
    assert!(regular_file.contains("MOVEFILE_WRITE_THROUGH"));
    assert!(!regular_file.contains("MOVEFILE_REPLACE_EXISTING"));
}
