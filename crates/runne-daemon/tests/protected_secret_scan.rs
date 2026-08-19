#[path = "support/secret_scan.rs"]
mod secret_scan;

use std::io::Cursor;

use secret_scan::{RepresentationClass, ScanError, SecretRepresentation, SecretScanner};

fn raw(bytes: &[u8]) -> SecretRepresentation {
    SecretRepresentation {
        class: RepresentationClass::Raw,
        bytes: bytes.to_vec(),
    }
}

fn windows_reference_present(haystack: &[u8], representations: &[SecretRepresentation]) -> bool {
    representations.iter().any(|representation| {
        haystack
            .windows(representation.bytes.len())
            .any(|window| window == representation.bytes)
    })
}

fn scanner_present(haystack: &[u8], representations: Vec<SecretRepresentation>) -> bool {
    SecretScanner::new(representations)
        .unwrap_or_else(|_| panic!("valid reference fixture"))
        .scan_reader(Cursor::new(haystack))
        .unwrap_or_else(|_| panic!("fixture reader"))
        .is_some()
}

#[test]
fn scanner_matches_windows_reference_for_presence_fixtures() {
    let fixtures: Vec<(Vec<u8>, Vec<SecretRepresentation>)> = vec![
        (b"nothing here".to_vec(), vec![raw(b"secret")]),
        (b"secret at start".to_vec(), vec![raw(b"secret")]),
        (b"at end secret".to_vec(), vec![raw(b"secret")]),
        (b"aaaa".to_vec(), vec![raw(b"aa"), raw(b"aaa")]),
        (
            b"prefix-long".to_vec(),
            vec![raw(b"prefix"), raw(b"prefix-long")],
        ),
        (b"chunk-split-secret".to_vec(), vec![raw(b"split-secret")]),
        (b"zero\0secret\0byte".to_vec(), vec![raw(b"\0secret\0")]),
    ];
    for (haystack, representations) in fixtures {
        assert_eq!(
            scanner_present(&haystack, representations.clone()),
            windows_reference_present(&haystack, &representations),
            "presence must match the old windows reference",
        );
    }
}

#[test]
fn scanner_rejects_empty_pattern_set_and_empty_pattern() {
    assert!(matches!(
        SecretScanner::new(vec![]),
        Err(ScanError::EmptyPatternSet)
    ));
    assert!(matches!(
        SecretScanner::new(vec![raw(b"")]),
        Err(ScanError::EmptyPattern {
            input_index: 0,
            class: RepresentationClass::Raw
        })
    ));
}

#[test]
fn scanner_deduplicates_exact_patterns_in_first_seen_order() {
    let scanner = SecretScanner::new(vec![
        raw(b"alpha"),
        SecretRepresentation {
            class: RepresentationClass::LowerHex,
            bytes: b"alpha".to_vec(),
        },
        SecretRepresentation {
            class: RepresentationClass::UpperHex,
            bytes: b"beta".to_vec(),
        },
    ])
    .unwrap_or_else(|_| panic!("deduplicated matcher"));
    assert_eq!(
        scanner
            .scan_reader(Cursor::new(b"alpha"))
            .unwrap_or_else(|_| panic!("reader")),
        Some(secret_scan::MatchMetadata {
            pattern_id: 0,
            representation_class: RepresentationClass::Raw,
        })
    );
    assert_eq!(
        scanner
            .scan_reader(Cursor::new(b"beta"))
            .unwrap_or_else(|_| panic!("reader")),
        Some(secret_scan::MatchMetadata {
            pattern_id: 1,
            representation_class: RepresentationClass::UpperHex,
        })
    );
}

#[derive(Clone)]
struct ChunkedReader {
    chunks: Vec<Vec<u8>>,
    index: usize,
    offset: usize,
    fail_after_chunks: bool,
}

impl std::io::Read for ChunkedReader {
    fn read(&mut self, output: &mut [u8]) -> std::io::Result<usize> {
        if self.index == self.chunks.len() {
            if self.fail_after_chunks {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Interrupted,
                    "custom protected-looking I/O text must stay private",
                ));
            }
            return Ok(0);
        }
        let chunk = &self.chunks[self.index];
        let count = output.len().min(chunk.len() - self.offset);
        output[..count].copy_from_slice(&chunk[self.offset..self.offset + count]);
        self.offset += count;
        if self.offset == chunk.len() {
            self.index += 1;
            self.offset = 0;
        }
        Ok(count)
    }
}

struct FailingReader;

impl std::io::Read for FailingReader {
    fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
        Err(std::io::Error::new(
            std::io::ErrorKind::Interrupted,
            "custom I/O text must stay private",
        ))
    }
}

fn panic_text(action: impl FnOnce() + std::panic::UnwindSafe) -> String {
    let payload = std::panic::catch_unwind(action).expect_err("assertion must fail");
    payload
        .downcast_ref::<String>()
        .cloned()
        .or_else(|| payload.downcast_ref::<&str>().map(ToString::to_string))
        .expect("string panic")
}

#[test]
fn scanner_detects_all_six_representation_classes() {
    let representations = vec![
        (RepresentationClass::Raw, b"raw-value".as_slice()),
        (RepresentationClass::Base64, b"cmF3LXZhbHVl".as_slice()),
        (
            RepresentationClass::Base64Unpadded,
            b"dW5wYWRkZWQ".as_slice(),
        ),
        (RepresentationClass::Base64Url, b"dXJsX3NhZmU".as_slice()),
        (RepresentationClass::LowerHex, b"6c6f776572".as_slice()),
        (RepresentationClass::UpperHex, b"5550504552".as_slice()),
    ];
    for (class, bytes) in representations {
        let scanner = SecretScanner::new(vec![SecretRepresentation {
            class,
            bytes: bytes.to_vec(),
        }])
        .unwrap_or_else(|_| panic!("valid class"));
        assert_eq!(
            scanner
                .scan_reader(Cursor::new(bytes))
                .unwrap_or_else(|_| panic!("reader"))
                .unwrap()
                .representation_class,
            class
        );
    }
}

#[test]
fn streaming_scanner_finds_chunk_spanning_match() {
    let scanner =
        SecretScanner::new(vec![raw(b"cross-chunk")]).unwrap_or_else(|_| panic!("scanner"));
    let reader = ChunkedReader {
        chunks: vec![b"cross-".to_vec(), b"chunk".to_vec()],
        index: 0,
        offset: 0,
        fail_after_chunks: false,
    };
    assert_eq!(
        scanner
            .scan_reader(reader)
            .unwrap_or_else(|_| panic!("reader"))
            .unwrap()
            .pattern_id,
        0
    );
}

#[test]
fn streaming_scanner_fails_closed_on_reader_error() {
    let scanner = SecretScanner::new(vec![raw(b"io-secret-never-render")])
        .unwrap_or_else(|_| panic!("scanner"));
    assert!(matches!(
        scanner.scan_reader(FailingReader),
        Err(ScanError::Io {
            kind: std::io::ErrorKind::Interrupted
        })
    ));
    let message =
        panic_text(|| secret_scan::assert_reader_absent(&scanner, "failing sink", FailingReader));
    assert!(message.contains("failing sink"));
    assert!(message.contains("Interrupted"));
    assert!(!message.contains("custom I/O text must stay private"));
    assert!(!message.contains("io-secret-never-render"));
}

#[test]
fn streaming_scanner_fails_closed_after_match_then_reader_error() {
    let scanner = SecretScanner::new(vec![raw(b"late-protected-pattern")])
        .unwrap_or_else(|_| panic!("scanner"));
    let reader = ChunkedReader {
        chunks: vec![b"late-protected-pattern".to_vec()],
        index: 0,
        offset: 0,
        fail_after_chunks: true,
    };
    assert!(matches!(
        scanner.scan_reader(reader.clone()),
        Err(ScanError::Io {
            kind: std::io::ErrorKind::Interrupted
        })
    ));
    let message =
        panic_text(|| secret_scan::assert_reader_absent(&scanner, "late failing sink", reader));
    assert!(message.contains("late failing sink") && message.contains("Interrupted"));
    assert!(!message.contains("custom protected-looking I/O text must stay private"));
    assert!(!message.contains("late-protected-pattern"));
}

#[test]
fn separate_files_do_not_form_one_haystack() {
    let scanner = SecretScanner::new(vec![raw(b"abcdef")]).unwrap_or_else(|_| panic!("scanner"));
    let directory = tempfile::tempdir().expect("temporary directory");
    let left = directory.path().join("left.bin");
    let right = directory.path().join("right.bin");
    std::fs::write(&left, b"abc").expect("left fixture");
    std::fs::write(&right, b"def").expect("right fixture");
    secret_scan::assert_file_absent(&scanner, "left file", &left);
    secret_scan::assert_file_absent(&scanner, "right file", &right);
}

#[test]
fn assertion_output_is_redacted_for_every_sink_class() {
    let scanner = SecretScanner::new(vec![raw(b"do-not-render-protected-bytes")])
        .unwrap_or_else(|_| panic!("scanner"));
    for sink in [
        "renderer frames",
        "renderer-safe errors",
        "temporary tree",
        "export",
        "backup",
        "captured stdout",
        "captured stderr/logs",
        "runtime tree",
        "temporary tree",
        "tracked fixture",
    ] {
        let message = panic_text(|| {
            secret_scan::assert_reader_absent(
                &scanner,
                sink,
                Cursor::new(b"do-not-render-protected-bytes"),
            )
        });
        assert!(
            message.contains(sink)
                && message.contains("pattern_id=0")
                && message.contains("representation_class=Raw")
        );
        assert!(!message.contains("do-not-render-protected-bytes"));
    }
}

#[test]
fn file_assertion_reports_sink_and_path() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let path = directory.path().join("audited.bin");
    std::fs::write(&path, b"file-only-protected").expect("fixture file");
    let scanner =
        SecretScanner::new(vec![raw(b"file-only-protected")]).unwrap_or_else(|_| panic!("scanner"));
    let message = panic_text(|| secret_scan::assert_file_absent(&scanner, "file sink", &path));
    assert!(message.contains("file sink") && message.contains(path.to_string_lossy().as_ref()));
    assert!(!message.contains("file-only-protected"));
}
