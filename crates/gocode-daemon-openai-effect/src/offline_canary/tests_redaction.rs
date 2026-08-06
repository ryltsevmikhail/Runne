//! Redaction hardening: JSON-escape marker normalization and no-I/O guards.

use super::tests_lifecycle::{BASE, git, read};

const MAX_NORMALIZE_ROUNDS: usize = 8;
const PRODUCTION_PATHS: [&str; 8] = [
    "crates/gocode-provider-openai/src/canary.rs",
    "crates/gocode-provider-openai/src/canary/contract.rs",
    "crates/gocode-provider-openai/src/canary/accounting.rs",
    "crates/gocode-daemon-openai-effect/src/offline_canary.rs",
    "crates/gocode-daemon-openai-effect/src/offline_canary/authority.rs",
    "crates/gocode-daemon-openai-effect/src/offline_canary/approvals.rs",
    "crates/gocode-daemon-openai-effect/src/offline_canary/fence.rs",
    "crates/gocode-daemon-openai-effect/src/offline_canary/report.rs",
];

fn markers() -> impl Iterator<Item = &'static str> {
    concat!(
        "Reply with exactly: OK|OK|Authorization|authorization|api_key|OPENAI_API_KEY|",
        "proxy|credential|metadata|previous_response_id|provider-response-id|request-id|",
        "idempotency-key|/private/keychain/path|header-secret|https://dynamic.invalid|",
        "reqwest error|TLS error|serde error|SQLite error|runtime error|Debug payload|",
        "stack trace|ENV_SECRET",
    )
    .split('|')
}
pub(super) fn assert_markers_absent(value: &str) {
    assert_eq!(
        json_escape("https://dynamic.invalid"),
        r#"https:\/\/dynamic.invalid"#
    );
    let controls = "\"\\/\u{08}\u{0c}\n\r\t\u{01}";
    assert_eq!(json_escape(controls), r#"\"\\\/\b\f\n\r\t\u0001"#);
    assert!(!is_violating(value), "forbidden marker in rendered value");
}
fn json_escape(value: &str) -> String {
    let mut escaped = String::new();
    for character in value.chars() {
        match character {
            '"' => escaped.push_str("\\\""),
            '\\' => escaped.push_str("\\\\"),
            '/' => escaped.push_str("\\/"),
            '\u{08}' => escaped.push_str("\\b"),
            '\u{0c}' => escaped.push_str("\\f"),
            '\n' => escaped.push_str("\\n"),
            '\r' => escaped.push_str("\\r"),
            '\t' => escaped.push_str("\\t"),
            control if control <= '\u{1f}' => {
                escaped.push_str(&format!("\\u{:04x}", control as u32))
            }
            character => escaped.push(character),
        }
    }
    escaped
}
fn unicode_escape(marker: &str) -> String {
    marker
        .chars()
        .map(|character| format!("\\u{:04x}", character as u32))
        .collect()
}
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
fn hex_escape(chars: &[char], start: usize) -> Option<u32> {
    let mut value = 0u32;
    for offset in 0..4 {
        value = (value << 4) | chars.get(start + offset)?.to_digit(16)?;
    }
    Some(value)
}
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
fn is_violating(value: &str) -> bool {
    let raw = markers().any(|marker| {
        value.contains(marker)
            || value.contains(&json_escape(marker))
            || value.contains(&unicode_escape(marker))
    });
    if raw {
        return true;
    }
    match normalize(value) {
        Ok(normalized) => markers().any(|marker| normalized.contains(marker)),
        Err(()) => true,
    }
}

#[test]
#[rustfmt::skip]
fn mixed_escaped_marker_normalizes_and_is_detected() {
    assert_eq!(normalize(r#"Auth\u006frization"#), Ok("Authorization".to_owned()));
    assert!(is_violating(r#"Auth\u006frization"#));
}
#[test]
#[rustfmt::skip]
fn escaped_slash_marker_is_detected_after_normalization() {
    assert_eq!(normalize(r#"https:\/\/dynamic.invalid"#), Ok("https://dynamic.invalid".to_owned()));
    assert!(is_violating(r#"https:\/\/dynamic.invalid"#));
}
#[test]
#[rustfmt::skip]
fn double_escaped_marker_is_detected_at_fixed_point() {
    assert_eq!(normalize(r#"\\u0041uthorization"#), Ok("Authorization".to_owned()));
    assert!(is_violating(r#"\\u0041uthorization"#));
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
        let allowed: &[&str] = if path.starts_with("crates/gocode-provider-openai/") {
            &["core::", "sha2::", "super::"]
        } else {
            &["core::", "gocode_provider_openai::canary::", "super::"]
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
fn manifests_are_byte_identical_to_base() {
    let output = git(&[
        "ls-files",
        "Cargo.toml",
        "Cargo.lock",
        "crates/*/Cargo.toml",
    ]);
    assert!(output.stdout.len() <= 4_096);
    let stdout = String::from_utf8(output.stdout).expect("bounded UTF-8 manifests");
    let paths: Vec<&str> = stdout.lines().filter(|line| !line.is_empty()).collect();
    assert!(!paths.is_empty() && paths.len() <= 64);
    for path in paths {
        assert!(!path.is_empty() && path.len() <= 256);
        let expected = git(&["show", &format!("{BASE}:{path}")]);
        assert!(
            read(path).as_bytes() == expected.stdout,
            "manifest drift: {path}"
        );
    }
}

fn use_head(line: &str) -> Option<&str> {
    let trimmed = line.trim_start();
    let head = ["use ", "pub use ", "pub(super) use ", "pub(crate) use "]
        .into_iter()
        .find_map(|prefix| trimmed.strip_prefix(prefix))
        .or_else(|| {
            trimmed
                .strip_prefix("pub(in ")
                .and_then(|rest| rest.split_once(") use ").map(|(_, head)| head))
        })?;
    let end = head.find(['{', ';', '*']).unwrap_or(head.len());
    Some(head[..end].trim_end())
}
fn import_scan_violation<'a>(
    content: &'a str,
    allowed: &[&str],
    declared: &[&str],
) -> Option<&'a str> {
    content.lines().find(|line| match use_head(line) {
        Some(head) if !head.is_empty() => {
            let root = head.split("::").next().unwrap_or("");
            !allowed.iter().any(|root| head.starts_with(root)) && !declared.contains(&root)
        }
        Some(_) => true,
        None => false,
    })
}

fn declared_modules(content: &str) -> Vec<&str> {
    content
        .lines()
        .filter_map(|line| {
            let line = line.trim();
            let name = line
                .strip_prefix("mod ")?
                .split_whitespace()
                .next()?
                .trim_end_matches(';');
            (!name.is_empty() && name.chars().all(|c| c.is_alphanumeric() || c == '_'))
                .then_some(name)
        })
        .collect()
}
