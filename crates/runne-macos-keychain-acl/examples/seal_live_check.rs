//! Live Secure Enclave / DataProtection-keychain evidence probe for the seal path.
//!
//! This probe `CREATES` a real Secure Enclave key in the `DataProtection` keychain
//! for the supplied profile identity digest (label prefix
//! `dev.runne.security-transaction-seal.v1.`). The calling binary must be
//! codesigned with `DataProtection`-keychain-compatible entitlements.
//!
//! Example: `cargo run -p runne-macos-keychain-acl --example seal_live_check -- 64-hex-digest`

use std::process::ExitCode;

#[cfg(target_os = "macos")]
use runne_macos_keychain_acl::{KeychainAclError, SecurityProfileProcessLock};
#[cfg(target_os = "macos")]
use std::io::Write as _;

#[cfg(target_os = "macos")]
const USAGE: &str = "usage: seal_live_check <64-char lowercase hex profile identity digest>";

#[cfg(target_os = "macos")]
fn emit(line: &str) {
    println!("{line}");
    let _ = std::io::stdout().flush();
}

#[cfg(target_os = "macos")]
fn fail(stage: &str, error: KeychainAclError) -> ExitCode {
    emit(&format!("stage={stage} status=err debug={error:?}"));
    ExitCode::from(1)
}

#[cfg(target_os = "macos")]
const fn hex_value(byte: u8) -> u8 {
    match byte {
        b'0'..=b'9' => byte - b'0',
        _ => byte - b'a' + 10,
    }
}

#[cfg(target_os = "macos")]
fn parse_digest(argument: &str) -> Option<[u8; 32]> {
    let bytes = argument.as_bytes();
    let lowercase_hex = |&byte: &u8| byte.is_ascii_lowercase() || byte.is_ascii_digit();
    if bytes.len() != 64 || !bytes.iter().all(lowercase_hex) {
        return None;
    }
    Some(std::array::from_fn(|index| {
        (hex_value(bytes[2 * index]) << 4) | hex_value(bytes[2 * index + 1])
    }))
}

#[cfg(target_os = "macos")]
fn main() -> ExitCode {
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    let [argument] = arguments.as_slice() else {
        eprintln!("{USAGE}");
        return ExitCode::from(2);
    };
    let Some(digest) = parse_digest(argument).filter(|digest| *digest != [0; 32]) else {
        eprintln!("{USAGE}");
        return ExitCode::from(2);
    };
    emit("stage=acquire status=start");
    let lock = match SecurityProfileProcessLock::acquire(digest) {
        Ok(lock) => lock,
        Err(error) => return fail("acquire", error),
    };
    emit("stage=acquire status=ok");
    emit("stage=seal status=start");
    let seal = match lock.seal(digest, [1; 32], 1, [2; 32], [0; 32]) {
        Ok(seal) => seal,
        Err(error) => return fail("seal", error),
    };
    emit("stage=seal status=ok");
    emit("stage=verify status=start");
    if let Err(error) = lock.verify(digest, [1; 32], 1, [2; 32], [0; 32], seal.as_bytes()) {
        return fail("verify", error);
    }
    drop(lock);
    emit("stage=verify status=ok");
    emit("result=ok");
    ExitCode::SUCCESS
}

#[cfg(not(target_os = "macos"))]
fn main() -> ExitCode {
    eprintln!("seal_live_check requires macOS and was not executed on this platform");
    ExitCode::from(2)
}
