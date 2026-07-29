//! Integration tests for daemon token lifecycle.

use gocode_daemon::token::{DaemonToken, TokenManager};
use std::fs;
use std::io::Write;
use tempfile::TempDir;

#[test]
fn provision_creates_token() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("token");

    let token = TokenManager::provision(&path).unwrap();
    assert_eq!(token.0.len(), 32);

    let data = fs::read(&path).unwrap();
    assert_eq!(data.len(), 32);
    assert_eq!(&data[..], &token.0[..]);
}

#[test]
fn provision_existing_fails() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("token");

    TokenManager::provision(&path).unwrap();
    let err = TokenManager::provision(&path).unwrap_err();
    let msg = format!("{err}");
    assert!(
        msg.contains("token error"),
        "expected token error, got: {msg}"
    );
}

#[test]
fn load_roundtrip() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("token");

    let token = TokenManager::provision(&path).unwrap();
    let loaded = TokenManager::load(&path).unwrap();
    assert_eq!(token, loaded);
}

#[test]
fn load_wrong_size_fails() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("token");

    let mut file = fs::File::create(&path).unwrap();
    file.write_all(&[0u8; 16]).unwrap();
    drop(file);

    let err = TokenManager::load(&path).unwrap_err();
    let msg = format!("{err}");
    assert!(msg.contains("32"), "expected size error, got: {msg}");
}

#[test]
fn verify_correct_token() {
    let token = DaemonToken([0xABu8; 32]);
    assert!(TokenManager::verify(&token, &[0xABu8; 32]));
}

#[test]
fn verify_wrong_token() {
    let token = DaemonToken([0xABu8; 32]);
    assert!(!TokenManager::verify(&token, &[0xCDu8; 32]));
}

#[test]
fn verify_short_input() {
    let token = DaemonToken([0xABu8; 32]);
    assert!(!TokenManager::verify(&token, &[0xABu8; 16]));
}

#[test]
fn debug_output_never_contains_raw_or_hex_token_material() {
    let token = DaemonToken([0xABu8; 32]);
    let debug = format!("{token:?}");
    assert_eq!(debug, "DaemonToken(<redacted>)");
    assert!(!debug.contains(&hex::encode(token.0)));
}

#[test]
fn load_nonexistent_fails() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("nonexistent");

    let err = TokenManager::load(&path).unwrap_err();
    let msg = format!("{err}");
    assert!(
        msg.contains("token error") || msg.contains("not found"),
        "expected token error, got: {msg}"
    );
}
