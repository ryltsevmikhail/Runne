//! Local-only legacy seed half of the slice-E qualification fixture.
//!
//! Runs as the staged writer binary — the one trusted app in the seeded
//! item's exact ACL — so the generation-0 legacy item is created by a
//! process the authorized import will accept as its reader-side owner.
//! Inert outside the closed local-native-enrollment-test fixture.

use std::io::Read as _;
use std::path::PathBuf;

use runne_secure_store::ProviderCredentialSourceRevision;

use crate::ProcessOutcome;

pub const MODE: &str = "__slice-e-legacy-seed-v1";

#[must_use]
pub fn selected(arguments: &[std::ffi::OsString]) -> bool {
    arguments.len() == 1
        && arguments[0] == MODE
        && local_opt_in(
            std::env::var_os("RUNNE_LOCAL_NATIVE_ENROLLMENT_TEST").as_deref(),
            std::env::var_os("RUNNE_SLICE_E_INNER_CASE").as_deref(),
        )
}

fn local_opt_in(enrollment: Option<&std::ffi::OsStr>, selector: Option<&std::ffi::OsStr>) -> bool {
    enrollment == Some(std::ffi::OsStr::new("1")) && selector == Some(std::ffi::OsStr::new(MODE))
}

#[must_use]
pub fn outcome() -> ProcessOutcome {
    match run() {
        Ok(()) => ProcessOutcome {
            stdout: String::new(),
            stderr: String::new(),
            exit_code: 0,
        },
        Err(stage) => ProcessOutcome {
            stdout: String::new(),
            stderr: format!("legacy-seed-closed-stage:{stage}\n"),
            exit_code: 1,
        },
    }
}

fn run() -> Result<(), &'static str> {
    // The synthetic canary material arrives over stdin from the orchestrating
    // parent; it never travels through the environment or argv.
    let mut material = String::new();
    std::io::stdin()
        .read_to_string(&mut material)
        .map_err(|_| "material-stdin")?;
    let material = material.trim().to_owned();
    let fixture = canonicalized(std::env::var_os("RUNNE_SLICE_E_FIXTURE_ROOT").as_deref())
        .ok_or("fixture-root")?;
    let home = canonicalized(std::env::var_os("HOME").as_deref()).ok_or("fixture-home")?;
    if home != fixture.join("home") {
        return Err("fixture-home-mismatch");
    }
    let keychain_env = canonicalized(std::env::var_os("RUNNE_CI_MACOS_KEYCHAIN").as_deref())
        .ok_or("keychain-env")?;
    let keychain_expected = home.join("Library/Keychains/runne-ci.keychain-db");
    if keychain_env != keychain_expected {
        return Err("keychain-mismatch");
    }
    let writer = canonicalized(
        std::env::current_exe()
            .ok()
            .as_deref()
            .map(std::path::Path::as_os_str),
    )
    .ok_or("writer-self")?;
    let writer_expected = fixture.join("Runne.app/Contents/MacOS/runne");
    if writer != writer_expected {
        return Err("writer-mismatch");
    }
    let reader = fixture.join("Runne.app/Contents/MacOS/runned");

    let store = runne_secure_store::NativeProviderCredentialStore::new();
    let access = runne_secure_store::ProviderCredentialAccessPolicy::new(&writer, &reader)
        .map_err(|_| "access-policy")?;
    let exact = runne_macos_keychain_acl::ExactKeychainAccess::new(&writer, &reader)
        .map_err(|_| "exact-access")?;
    let material = runne_secure_store::ProviderCredentialMaterial::new(material.into_bytes())
        .map_err(|_| "material")?;
    let revision = ProviderCredentialSourceRevision::new([
        0x5c, 0x4a, 0x11, 0xf2, 0x9d, 0x63, 0xb8, 0x27, 0x40, 0x71, 0xe5, 0x0a, 0xd3, 0x96, 0x18,
        0x6f,
    ])
    .map_err(|_| "revision")?;
    store
        .seed_generation_zero_source_scenario(
            runne_secure_store::ProviderCredentialId::OpenAi,
            &material,
            &access,
            &exact,
            revision,
        )
        .map_err(|_| "seed")
}

fn canonicalized(value: Option<&std::ffi::OsStr>) -> Option<PathBuf> {
    std::fs::canonicalize(value?).ok()
}
