//! Live Secure Enclave evidence probe for the macOS mutation-payload envelope.
//!
//! The probe must be codesigned with the DataProtection-keychain entitlements
//! and the Developer ID provisioning profile of `com.runne.desktop`. It reuses
//! the profile's existing seal key (label
//! `dev.runne.security-transaction-seal.v1.<digest>`) and exercises the full
//! encrypt/decrypt path, its fail-closed rejections, and anchored admission.
//!
//! Build with `cargo build -p runne-local-store --example
//! macos_payload_admission_check`, sign the containing bundle, and launch it
//! through `LaunchServices` with the 64-char hex profile digest, optionally
//! followed by a log path.

use std::process::ExitCode;

#[cfg(target_os = "macos")]
use runne_local_store::LocalStore;
#[cfg(target_os = "macos")]
use runne_secure_store::{MacOsKeychainStore, SecureStore, SecurityProfileLock};
#[cfg(target_os = "macos")]
use sha2::{Digest as _, Sha256};
#[cfg(target_os = "macos")]
use std::io::Write as _;

#[cfg(target_os = "macos")]
const USAGE: &str =
    "usage: macos_payload_admission_check <64-char lowercase hex profile digest> [log path]";
#[cfg(target_os = "macos")]
const DATABASE: [u8; 32] = [0x11; 32];
#[cfg(target_os = "macos")]
const AAD: &[u8] = b"runne/live-check/mutation-payload/aad/v1";
#[cfg(target_os = "macos")]
const PLAINTEXT: &[u8] = b"runne live mutation payload round-trip";
#[cfg(target_os = "macos")]
static LOG_PATH: std::sync::OnceLock<String> = std::sync::OnceLock::new();

#[cfg(target_os = "macos")]
fn emit(line: &str) {
    println!("{line}");
    if let Some(path) = LOG_PATH.get()
        && let Ok(mut file) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
    {
        let _ = writeln!(file, "{line}");
    }
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
fn derive(profile: [u8; 32], domain: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(profile);
    hasher.finalize().into()
}

#[cfg(target_os = "macos")]
fn hex(digest: [u8; 32]) -> String {
    let mut value = String::with_capacity(64);
    for byte in digest {
        use std::fmt::Write as _;
        let _ = write!(value, "{byte:02x}");
    }
    value
}

#[cfg(target_os = "macos")]
fn expect_rejected(label: &str, result: Result<zeroize::Zeroizing<Vec<u8>>, String>) -> bool {
    match result {
        Ok(_) => {
            emit(&format!("stage={label} status=err detail=accepted"));
            false
        }
        Err(detail) => {
            emit(&format!(
                "stage={label} status=ok detail=rejected({detail})"
            ));
            true
        }
    }
}

#[cfg(target_os = "macos")]
fn check_rejections(
    lock: &SecurityProfileLock<'_>,
    envelope: &[u8],
) -> Result<(), (String, String)> {
    let decrypt = |database: [u8; 32], aad: &[u8], encoded: &[u8]| {
        lock.decrypt_mutation_payload(database, aad, encoded)
            .map_err(|error| format!("{error:?}"))
    };
    let mut accepted =
        expect_rejected("wrong-aad", decrypt(DATABASE, b"runne/other/aad", envelope));
    accepted &= expect_rejected("wrong-database", decrypt([0x22; 32], AAD, envelope));
    let mut tampered_body = envelope.to_vec();
    let last = tampered_body.len() - 1;
    tampered_body[last] ^= 0x01;
    accepted &= expect_rejected("tampered-body", decrypt(DATABASE, AAD, &tampered_body));
    let mut tampered_key = envelope.to_vec();
    tampered_key[12] ^= 0x01;
    accepted &= expect_rejected("tampered-key", decrypt(DATABASE, AAD, &tampered_key));
    accepted &= expect_rejected(
        "truncated",
        decrypt(DATABASE, AAD, &envelope[..envelope.len() - 1]),
    );
    accepted &= expect_rejected("garbage", decrypt(DATABASE, AAD, &[0_u8; 96]));
    if accepted {
        Ok(())
    } else {
        Err((
            "negatives".to_owned(),
            "a rejection was accepted".to_owned(),
        ))
    }
}

#[cfg(target_os = "macos")]
fn check_foreign_profile(profile: [u8; 32], envelope: &[u8]) -> Result<(), (String, String)> {
    let foreign = derive(profile, b"runne/live-check/foreign-profile/v1");
    if foreign == profile || foreign == [0; 32] {
        return Err(("foreign-profile".to_owned(), "degenerate digest".to_owned()));
    }
    let store = MacOsKeychainStore::for_security_profile(hex(foreign), foreign);
    let lock = store
        .acquire_security_profile_lock(foreign)
        .map_err(|error| ("foreign-profile".to_owned(), format!("{error:?}")))?;
    let rejected = expect_rejected(
        "foreign-profile",
        lock.decrypt_mutation_payload(DATABASE, AAD, envelope)
            .map_err(|error| format!("{error:?}")),
    );
    drop(lock);
    if rejected {
        Ok(())
    } else {
        Err((
            "foreign-profile".to_owned(),
            "foreign lock decrypted".to_owned(),
        ))
    }
}

#[cfg(target_os = "macos")]
fn check_admission(profile: [u8; 32]) -> Result<(), (String, String)> {
    let admission = derive(profile, b"runne/live-check/admission-profile/v1");
    let directory = std::path::PathBuf::from("/tmp/runne-payload-check-admission");
    std::fs::create_dir_all(&directory)
        .map_err(|error| ("admission".to_owned(), error.to_string()))?;
    let path = directory.join("payload-admission.sqlite3");
    let store = MacOsKeychainStore::for_security_profile(hex(admission), admission);
    emit("stage=admission status=start");
    let opened = LocalStore::open_anchored(&path, &store, admission)
        .map_err(|error| ("admission".to_owned(), format!("{error:?}")))?;
    drop(opened);
    let reopened = LocalStore::open_anchored(&path, &store, admission)
        .map_err(|error| ("admission-reopen".to_owned(), format!("{error:?}")))?;
    drop(reopened);
    emit("stage=admission status=ok");
    Ok(())
}

#[cfg(target_os = "macos")]
fn run(profile: [u8; 32]) -> Result<(), (String, String)> {
    let store = MacOsKeychainStore::for_security_profile(hex(profile), profile);
    emit("stage=acquire status=start");
    let lock = store
        .acquire_security_profile_lock(profile)
        .map_err(|error| ("acquire".to_owned(), format!("{error:?}")))?;
    emit("stage=acquire status=ok");
    if !lock.supports_mutation_payload_encryption() {
        return Err((
            "supports".to_owned(),
            "macOS lock reports no payload encryption".to_owned(),
        ));
    }
    emit("stage=supports status=ok");

    let envelope = lock
        .encrypt_mutation_payload(DATABASE, AAD, PLAINTEXT)
        .map_err(|error| ("encrypt".to_owned(), format!("{error:?}")))?;
    if envelope
        .windows(PLAINTEXT.len())
        .any(|window| window == PLAINTEXT)
    {
        return Err(("encrypt".to_owned(), "plaintext in envelope".to_owned()));
    }
    emit(&format!("stage=encrypt status=ok bytes={}", envelope.len()));
    let opened = lock
        .decrypt_mutation_payload(DATABASE, AAD, &envelope)
        .map_err(|error| ("decrypt".to_owned(), format!("{error:?}")))?;
    if opened.as_slice() != PLAINTEXT {
        return Err(("decrypt".to_owned(), "plaintext mismatch".to_owned()));
    }
    emit("stage=decrypt status=ok");
    check_rejections(&lock, &envelope)?;
    drop(lock);
    check_foreign_profile(profile, &envelope)?;
    check_admission(profile)
}

#[cfg(target_os = "macos")]
fn main() -> ExitCode {
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    let (argument, log_path) = match arguments.as_slice() {
        [argument] => (argument, None),
        [argument, log] => (argument, Some(log.as_str())),
        _ => {
            eprintln!("{USAGE}");
            return ExitCode::from(2);
        }
    };
    let Some(profile) = parse_digest(argument).filter(|digest| *digest != [0; 32]) else {
        eprintln!("{USAGE}");
        return ExitCode::from(2);
    };
    if let Some(path) = log_path {
        let _ = LOG_PATH.set(path.to_owned());
    }
    let code = match run(profile) {
        Ok(()) => {
            emit("result=ok");
            0
        }
        Err((stage, detail)) => {
            emit(&format!("stage={stage} status=err detail={detail}"));
            1
        }
    };
    ExitCode::from(code)
}

#[cfg(not(target_os = "macos"))]
fn main() {
    eprintln!("macos_payload_admission_check is only meaningful on macOS");
}
