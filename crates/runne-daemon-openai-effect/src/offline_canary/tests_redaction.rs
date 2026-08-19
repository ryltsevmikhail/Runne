//! Redaction hardening: JSON-escape marker normalization and no-I/O guards.
use tempfile::tempdir;
#[rustfmt::skip]
use super::tests_lifecycle::{CANDIDATE_PATHS, GATE_ORACLE_PATHS, GUARDED_PATHS, SEMANTIC_GUARDED_PATHS, read, read_bounded, read_semantic_traceability};
const MAX_NORMALIZE_ROUNDS: usize = 8;
const MAX_SEMANTIC_BYTES: usize = 16_384;
const MAX_TRACEABILITY_LINE: usize = 1_024;
const TRACEABILITY_ROW: &str = "| 31 | Exact scope guard | `immutable_candidate_scope_and_guarded_bytes_are_exact_and_fail_closed`, `candidate_guard_partition_is_exact`, `every_guarded_path_rejects_non_candidate_bytes`, `gate_oracle_exclusions_are_exact_and_disjoint`, `production_has_no_non_test_authority_witness_impl` |";
#[rustfmt::skip]
const TRACEABILITY_SYMBOLS: [&str; 5] = ["immutable_candidate_scope_and_guarded_bytes_are_exact_and_fail_closed", "candidate_guard_partition_is_exact", "every_guarded_path_rejects_non_candidate_bytes", "gate_oracle_exclusions_are_exact_and_disjoint", "production_has_no_non_test_authority_witness_impl"];
#[rustfmt::skip]
const LEGACY_TRACEABILITY_SYMBOLS: [&str; 2] = ["working_tree_scope_and_protected_bytes_are_exact_and_fail_closed", "manifests_are_byte_identical_to_base"];
#[rustfmt::skip]
const PRODUCTION_PATHS: [&str; 8] = ["crates/runne-provider-openai/src/canary.rs", "crates/runne-provider-openai/src/canary/contract.rs", "crates/runne-provider-openai/src/canary/accounting.rs", "crates/runne-daemon-openai-effect/src/offline_canary.rs", "crates/runne-daemon-openai-effect/src/offline_canary/authority.rs", "crates/runne-daemon-openai-effect/src/offline_canary/approvals.rs", "crates/runne-daemon-openai-effect/src/offline_canary/fence.rs", "crates/runne-daemon-openai-effect/src/offline_canary/report.rs"];
#[rustfmt::skip]
const MARKERS: &str = "Reply with exactly: OK|OK|Authorization|authorization|api_key|OPENAI_API_KEY|proxy|credential|metadata|previous_response_id|provider-response-id|request-id|idempotency-key|/private/keychain/path|header-secret|https://dynamic.invalid|reqwest error|TLS error|serde error|SQLite error|runtime error|Debug payload|stack trace|ENV_SECRET";
#[rustfmt::skip]
fn markers() -> impl Iterator<Item = &'static str> { MARKERS.split('|') }
pub(super) fn assert_markers_absent(value: &str) {
    assert_eq!(
        json_escape("https://dynamic.invalid"),
        r#"https:\/\/dynamic.invalid"#
    );
    let controls = "\"\\/\u{08}\u{0c}\n\r\t\u{01}";
    assert_eq!(json_escape(controls), r#"\"\\\/\b\f\n\r\t\u0001"#);
    assert!(!is_violating(value), "forbidden marker in rendered value");
}
#[rustfmt::skip]
fn json_escape(value: &str) -> String { let mut escaped = String::new(); for character in value.chars() { match character { '"' => escaped.push_str("\\\""), '\\' => escaped.push_str("\\\\"), '/' => escaped.push_str("\\/"), '\u{08}' => escaped.push_str("\\b"), '\u{0c}' => escaped.push_str("\\f"), '\n' => escaped.push_str("\\n"), '\r' => escaped.push_str("\\r"), '\t' => escaped.push_str("\\t"), control if control <= '\u{1f}' => escaped.push_str(&format!("\\u{:04x}", control as u32)), character => escaped.push(character), } } escaped }
#[rustfmt::skip]
fn unicode_escape(marker: &str) -> String { marker.chars().map(|character| format!("\\u{:04x}", character as u32)).collect() }
fn normalize(value: &str) -> Result<String, ()> {
    let mut current = value.to_owned();
    let mut rounds = 0;
    loop {
        let decoded = decode_round(&current)?;
        if decoded == current {
            return Ok(current);
        }
        if decoded.len() >= current.len() {
            return Err(());
        }
        rounds += 1;
        if rounds > MAX_NORMALIZE_ROUNDS {
            return Err(());
        }
        current = decoded;
    }
}
fn decode_round(value: &str) -> Result<String, ()> {
    let chars: Vec<char> = value.chars().collect();
    let mut decoded = String::with_capacity(value.len());
    let mut index = 0;
    while index < chars.len() {
        if chars[index] != '\\' {
            decoded.push(chars[index]);
            index += 1;
            continue;
        }
        match *chars.get(index + 1).ok_or(())? {
            '"' => decoded.push('"'),
            '\\' => decoded.push('\\'),
            '/' => decoded.push('/'),
            'b' => decoded.push('\u{08}'),
            'f' => decoded.push('\u{0c}'),
            'n' => decoded.push('\n'),
            'r' => decoded.push('\r'),
            't' => decoded.push('\t'),
            'u' => {
                let first = hex_escape(&chars, index + 2).ok_or(())?;
                if (0xd800..=0xdbff).contains(&first) {
                    if let Some(character) = surrogate_escape(&chars, index, first) {
                        decoded.push(character);
                        index += 12;
                        continue;
                    }
                    return Err(());
                }
                if (0xdc00..=0xdfff).contains(&first) {
                    return Err(());
                }
                decoded.push(char::from_u32(first).ok_or(())?);
                index += 6;
                continue;
            }
            _ => return Err(()),
        }
        index += 2;
    }
    Ok(decoded)
}
#[rustfmt::skip]
fn hex_escape(chars: &[char], start: usize) -> Option<u32> { let mut value = 0u32; for offset in 0..4 { value = (value << 4) | chars.get(start + offset)?.to_digit(16)?; } Some(value) }
fn surrogate_escape(chars: &[char], index: usize, first: u32) -> Option<char> {
    if chars.get(index + 6) != Some(&'\\') || chars.get(index + 7) != Some(&'u') {
        return None;
    }
    let low = hex_escape(chars, index + 8)?;
    if !(0xdc00..=0xdfff).contains(&low) {
        return None;
    }
    char::from_u32(0x1_0000 + ((first - 0xd800) << 10) + (low - 0xdc00))
}
#[rustfmt::skip]
fn is_violating(value: &str) -> bool {
    let raw = markers().any(|marker| {
        value.contains(marker)
            || value.contains(&json_escape(marker))
            || value.contains(&unicode_escape(marker))
    });
    raw || normalize(value).map_or(true, |normalized| markers().any(|marker| normalized.contains(marker)))
}
#[test]
#[rustfmt::skip]
fn mixed_escaped_marker_normalizes_and_is_detected() {
    assert_eq!(normalize(r#"Auth\u006frization"#), Ok("Authorization".to_owned())); assert!(is_violating(r#"Auth\u006frization"#));
}
#[test]
#[rustfmt::skip]
fn escaped_slash_marker_is_detected_after_normalization() {
    assert_eq!(normalize(r#"https:\/\/dynamic.invalid"#), Ok("https://dynamic.invalid".to_owned())); assert!(is_violating(r#"https:\/\/dynamic.invalid"#));
}
#[test]
#[rustfmt::skip]
fn double_escaped_marker_is_detected_at_fixed_point() {
    assert_eq!(normalize(r#"\\u0041uthorization"#), Ok("Authorization".to_owned())); assert!(is_violating(r#"\\u0041uthorization"#));
}
#[test]
fn surrogate_pair_decodes_and_marker_is_detected() {
    assert_eq!(normalize(r#"\uD83D\uDE00"#), Ok("\u{1f600}".to_owned()));
    assert!(is_violating(r#"\uD83D\uDE00Authorization"#));
}
#[test]
fn malformed_escapes_fail_closed() {
    for malformed in [r#"\u00"#, r#"\uZZZZ"#, r#"\ud800"#] {
        assert!(normalize(malformed).is_err());
        assert!(is_violating(malformed));
    }
}
#[test]
#[rustfmt::skip]
fn clean_values_stay_clean_after_normalization() {
    assert_eq!(normalize("CanaryEvidence"), Ok("CanaryEvidence".to_owned()));
    for clean in ["CanaryEvidence", "closed debug output", "pure accounting result 42", r#"\u0061bc"#] {
        assert!(!is_violating(clean));
    }
}
#[test]
#[rustfmt::skip]
fn production_import_roots_are_allowlisted_and_fail_closed() {
    for path in PRODUCTION_PATHS {
        let content = read(path);
        let allowed: &[&str] = if path.starts_with("crates/runne-provider-openai/") {
            &["core::", "sha2::", "super::"]
        } else {
            &["core::", "runne_provider_openai::canary::", "super::"]
        };
        for token in ["crate::", "super::super::", "std::", "unsafe", "extern crate", "include_str!", "include_bytes!", "#[path]", "reqwest::", "tokio::", "hyper::", "env!", "option_env!", "include!"] {
            assert!(!content.contains(token), "forbidden {token} in {path}");
        }
        assert!(!content.contains("::*"), "wildcard import in {path}");
        let declared = declared_modules(&content);
        if let Some(line) = import_scan_violation(&content, allowed, &declared) {
            panic!("import not allowed: {line} in {path}");
        }
    }
}
#[test]
#[rustfmt::skip]
fn production_has_no_non_test_authority_witness_impl() {
    for path in PRODUCTION_PATHS {
        let content = read(path);
        for category in ["impl ApprovalTransactionAuthority for", "impl PossibleDispatchBoundaryMint for"] {
            assert!(!content.contains(category), "{category} in {path}");
        }
    }
}
#[test]
#[rustfmt::skip]
fn grouped_import_bypass_forms_fail_closed() {
    let declared: [&str; 0] = [];
    for bypass in ["use { reqwest::get };", "pub(in super) use { tokio::time };", "use { hyper::Client };"] {
        assert!(import_scan_violation(bypass, &["core::"], &declared).is_some(), "bypass not detected: {bypass}");
    }
    assert!(import_scan_violation("use core::fmt;", &["core::"], &declared).is_none());
}
#[test]
#[rustfmt::skip]
fn gate_oracle_exclusions_are_exact_and_disjoint() {
    let oracle_paths = ["crates/runne-daemon-openai-effect/src/offline_canary/tests_lifecycle.rs", "crates/runne-daemon-openai-effect/src/offline_canary/tests_redaction.rs"];
    assert_eq!(GATE_ORACLE_PATHS, oracle_paths);
    assert_eq!(SEMANTIC_GUARDED_PATHS, ["docs/traceability/TASK5_OPENAI_L4_CANARY.md"]);
    assert_eq!((CANDIDATE_PATHS.len(), GUARDED_PATHS.len(), SEMANTIC_GUARDED_PATHS.len(), oracle_paths.len()), (19, 16, 1, 2));
    assert!(oracle_paths.iter().all(|path| CANDIDATE_PATHS.contains(path)));
    assert!(oracle_paths.iter().all(|path| !GUARDED_PATHS.contains(path) && !SEMANTIC_GUARDED_PATHS.contains(path)));
    assert!(!oracle_paths.contains(&SEMANTIC_GUARDED_PATHS[0]));
}
#[test]
#[rustfmt::skip]
fn semantic_traceability_row_is_exact() {
    assert!(traceability_row_is_valid(read_semantic_traceability().as_bytes()));
}
#[test]
#[rustfmt::skip]
fn semantic_traceability_rejects_all_negative_fixtures() {
    let mut fixtures = vec![
        ("changed label", TRACEABILITY_ROW.replacen("Exact scope guard", "Changed", 1).into_bytes()),
        ("extra symbol", format!("{TRACEABILITY_ROW} `extra_sixth_symbol`").into_bytes()),
        ("missing row", b"| 30 | No-I/O boundary | `runtime_canary_sources_have_no_dangerous_api` |".to_vec()),
        ("duplicate exact row", format!("{TRACEABILITY_ROW}\n{TRACEABILITY_ROW}").into_bytes()),
        ("duplicate normalized row", format!("{TRACEABILITY_ROW}\n   {}", TRACEABILITY_ROW.trim_start_matches('|').trim_start()).into_bytes()),
        ("compact pipe duplicate", format!("{TRACEABILITY_ROW}\n|31| duplicate |").into_bytes()),
        ("compact bare duplicate", format!("{TRACEABILITY_ROW}\n31| duplicate |").into_bytes()),
        ("invalid UTF-8", vec![0xff]),
        ("over byte limit", vec![b'x'; MAX_SEMANTIC_BYTES + 1]),
        ("over line limit", vec![b'x'; MAX_TRACEABILITY_LINE + 1]),
    ];
    fixtures.extend(TRACEABILITY_SYMBOLS.map(|symbol| ("missing symbol", TRACEABILITY_ROW.replacen(symbol, "", 1).into_bytes())));
    fixtures.extend(LEGACY_TRACEABILITY_SYMBOLS.map(|legacy| ("legacy symbol", format!("{TRACEABILITY_ROW}\n{legacy}").into_bytes())));
    for (name, fixture) in fixtures { assert!(!traceability_row_is_valid(&fixture), "accepted {name}"); }
}
#[test] #[rustfmt::skip]
fn bounded_reader_rejects_directory() { let directory = tempdir().expect("private directory creates"); assert!(read_bounded(directory.path()).is_err()); }
#[cfg(unix)]
#[test] #[rustfmt::skip]
fn bounded_reader_opens_regular_file_and_rejects_symlink() {
    use std::{fs::File, io::Write};
    let directory = tempdir().expect("private directory creates");
    let target = directory.path().join("target");
    let link = directory.path().join("link");
    File::create(&target).expect("test target creates").write_all(b"ok").expect("test target writes");
    std::os::unix::fs::symlink(&target, &link).expect("test symlink creates");
    assert_eq!(read_bounded(&target).expect("regular target opens"), "ok");
    assert!(read_bounded(&link).is_err());
}
#[cfg(windows)]
#[test] #[rustfmt::skip]
fn bounded_reader_opens_regular_file_and_rejects_reparse_point() {
    use std::{fs::File, io::Write};
    let directory = tempdir().expect("private directory creates");
    let target = directory.path().join("target");
    let link = directory.path().join("link");
    File::create(&target).expect("test target creates").write_all(b"ok").expect("test target writes");
    std::os::windows::fs::symlink_file(&target, &link).expect("test reparse point creates");
    assert_eq!(read_bounded(&target).expect("regular target opens"), "ok");
    assert!(read_bounded(&link).is_err());
}
#[cfg(unix)]
#[test] #[rustfmt::skip]
fn bounded_reader_rejects_fifo_without_waiting() {
    use std::process::Command;
    let directory = tempdir().expect("private directory creates");
    let fifo = directory.path().join("fifo");
    assert!(Command::new("mkfifo").arg(&fifo).status().expect("mkfifo starts").success());
    assert_eq!(read_bounded(&fifo).unwrap_err().kind(), std::io::ErrorKind::InvalidData);
}
#[rustfmt::skip]
#[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "android", windows)))]
#[test]
fn bounded_reader_is_unsupported_without_a_no_follow_flag() {
    assert_eq!(read_bounded(std::path::Path::new("unsupported")).unwrap_err().kind(), std::io::ErrorKind::Unsupported);
}
#[rustfmt::skip]
fn traceability_row_is_valid(bytes: &[u8]) -> bool {
    if bytes.len() > MAX_SEMANTIC_BYTES { return false; }
    let Ok(text) = std::str::from_utf8(bytes) else { return false; };
    if text.split('\n').any(|line| line.len() > MAX_TRACEABILITY_LINE) { return false; }
    let rows: Vec<_> = text.split('\n').filter(|line| is_row_31(line)).collect();
    rows.len() == 1 && rows[0] == TRACEABILITY_ROW && TRACEABILITY_SYMBOLS.iter().all(|symbol| rows[0].match_indices(symbol).count() == 1) && LEGACY_TRACEABILITY_SYMBOLS.iter().all(|legacy| !text.contains(legacy))
}
#[rustfmt::skip]
fn is_row_31(line: &str) -> bool {
    let line = line.trim_start();
    let cell = line.strip_prefix('|').unwrap_or(line).split_once('|').map(|(cell, _)| cell);
    cell.is_some_and(|cell| cell.trim() == "31")
}
#[rustfmt::skip]
fn use_head(line: &str) -> Option<&str> {
    let trimmed = line.trim_start(); let head = ["use ", "pub use ", "pub(super) use ", "pub(crate) use "].into_iter().find_map(|prefix| trimmed.strip_prefix(prefix)).or_else(|| trimmed.strip_prefix("pub(in ").and_then(|rest| rest.split_once(") use ").map(|(_, head)| head)))?;
    let end = head.find(['{', ';', '*']).unwrap_or(head.len());
    Some(head[..end].trim_end())
}
#[rustfmt::skip]
fn import_scan_violation<'a>(
    content: &'a str,
    allowed: &[&str],
    declared: &[&str],
) -> Option<&'a str> {
    content.lines().find(|line| match use_head(line) { Some(head) if !head.is_empty() => {
        let root = head.split("::").next().unwrap_or(""); !allowed.iter().any(|root| head.starts_with(root)) && !declared.contains(&root)
    }
        Some(_) => true,
        None => false })
}
#[rustfmt::skip]
fn declared_modules(content: &str) -> Vec<&str> {
    content.lines().filter_map(|line| { let name = line.trim().strip_prefix("mod ")?.split_whitespace().next()?.trim_end_matches(';');
        (!name.is_empty() && name.chars().all(|c| c.is_alphanumeric() || c == '_')).then_some(name) }).collect()
}
