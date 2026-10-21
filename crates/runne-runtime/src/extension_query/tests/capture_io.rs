use super::super::*;
use super::fixtures::*;
use MetadataQueryError::*;
use std::io::{Seek, SeekFrom, Write};
// Breaks caught: cursor-relative read, unbounded growth, IO->empty fallback.
#[test]
fn nonzero_cursor_reads_whole_valid_json() {
    let mut f = file(json().as_bytes());
    f.seek(SeekFrom::Start(17)).unwrap();
    assert!(ConfiguredExtensionRegistry::capture(f, expected()).is_ok());
}
#[test]
fn eof_cursor_reads_whole_valid_json() {
    let mut f = file(json().as_bytes());
    f.seek(SeekFrom::End(0)).unwrap();
    assert!(ConfiguredExtensionRegistry::capture(f, expected()).is_ok());
}
#[test]
fn junk_prefix_at_valid_suffix_cursor_rejects() {
    let mut f = file(format!("junk{}", json()).as_bytes());
    f.seek(SeekFrom::Start(4)).unwrap();
    assert_eq!(
        ConfiguredExtensionRegistry::capture(f, expected()).unwrap_err(),
        InvalidSnapshot
    );
}
#[test]
fn capture_preserves_current_cursor() {
    for text in [json(), "junk".into()] {
        let mut f = file(text.as_bytes());
        f.seek(SeekFrom::Start(3)).unwrap();
        let mut alias = f.try_clone().unwrap();
        let _ = ConfiguredExtensionRegistry::capture(f, expected());
        assert_eq!(alias.stream_position().unwrap(), 3);
    }
}
#[test]
fn alias_seek_cannot_shift_absolute_capture() {
    let f = file(json().as_bytes());
    let mut alias = f.try_clone().unwrap();
    alias.seek(SeekFrom::End(0)).unwrap();
    assert!(ConfiguredExtensionRegistry::capture(f, expected()).is_ok());
}
#[test]
fn invalid_or_unreadable_file_never_becomes_empty() {
    for text in ["", "{", "{\"schema_version\":1}", "null"] {
        reject(text, InvalidSnapshot);
    }
    #[cfg(unix)]
    write_only_regular_fd_returns_source_unavailable();
}
#[cfg(unix)]
#[test]
fn write_only_regular_fd_returns_source_unavailable() {
    let temp = tempfile::NamedTempFile::new().unwrap();
    let f = std::fs::OpenOptions::new()
        .write(true)
        .open(temp.path())
        .unwrap();
    assert_eq!(
        ConfiguredExtensionRegistry::capture(f, expected()).unwrap_err(),
        SourceUnavailable
    );
}
#[cfg(unix)]
#[test]
fn nonregular_file_is_invalid_snapshot() {
    let f = std::fs::File::open("/dev/null").unwrap();
    assert_eq!(
        ConfiguredExtensionRegistry::capture(f, expected()).unwrap_err(),
        InvalidSnapshot
    );
}
#[test]
fn real_growth_after_metadata_is_bounded() {
    let f = file(b"");
    super::super::capture::inspect_file(&f).unwrap();
    let mut writer = f.try_clone().unwrap();
    writer.write_all(json().as_bytes()).unwrap();
    let bytes = super::super::bounded_capture::read_from_start(&f).unwrap();
    let owner = super::super::capture::publish(&bytes, expected()).unwrap();
    assert_eq!(owner.query(request()).unwrap().records.len(), 4);
}
#[test]
fn real_growth_beyond_limit_has_no_publication() {
    let f = file(b"");
    super::super::capture::inspect_file(&f).unwrap();
    f.set_len(1_048_577).unwrap();
    assert_eq!(
        super::super::bounded_capture::read_from_start(&f).unwrap_err(),
        LimitExceeded
    );
}
#[test]
fn truncate_or_mixed_bytes_need_exact_expected_semantics() {
    let text = json();
    let f = file(text.as_bytes());
    f.set_len(5).unwrap();
    assert_eq!(
        ConfiguredExtensionRegistry::capture(f, expected()).unwrap_err(),
        InvalidSnapshot
    );
    reject(&text.replace("local-tools", "mixed-tools"), InvalidSnapshot);
    // Valid whitespace overwrite preserves exact trusted normalized semantics.
    assert!(capture(&format!(" {text} \n")).is_ok());
}
#[cfg(not(unix))]
#[test]
fn nonunix_capture_fails_closed() {
    assert_eq!(
        ConfiguredExtensionRegistry::capture(file(json().as_bytes()), expected()).unwrap_err(),
        SourceUnavailable
    );
}
