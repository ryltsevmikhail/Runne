use std::collections::HashSet;
use std::sync::Arc;
use std::time::{Duration, Instant};

use base64::Engine as _;
use gocode_api::ProviderActivationBindingV1;
use gocode_app_core::{AppCore, RuntimeAvailability, RuntimeMode};
use gocode_application::prohibited_content::{
    CanonicalContentBoundary, ContentDisposition, ProhibitedContentPort,
};
use gocode_application::verification::export_port::VerificationExporter;
use gocode_domain::verification::backup::StreamInventory;
use gocode_domain::verification::digest::VerificationDigest;
use gocode_platform_desktop::{
    BundledRuntimeLifecycleState, BundledRuntimeProcessStatus, BundledRuntimeStopDisposition,
    DevelopmentBundledRuntimeLauncher, FirstActivationFaultPoint, ProtectedBundledRuntimeError,
    ProtectedBundledRuntimeLaunchSpec, ProtectedBundledRuntimeSupervisor,
};
use gocode_runtime_client::RuntimeTransportKind;
use gocode_security::SecretBroker;
use gocode_store::verification::backup_store::InMemoryBackupStore;
use rand::{RngCore as _, rngs::OsRng};

static PROCESS_FAULT_AUDIT_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

fn random_secret() -> [u8; 32] {
    let mut value = [0_u8; 32];
    while value == [0; 32] {
        OsRng.fill_bytes(&mut value);
    }
    value
}

fn material_representations(materials: &[Vec<u8>]) -> Vec<secret_scan::SecretRepresentation> {
    let mut representations = Vec::new();
    for material in materials {
        let standard = base64::engine::general_purpose::STANDARD.encode(material);
        representations.extend([
            secret_scan::SecretRepresentation {
                class: secret_scan::RepresentationClass::Raw,
                bytes: material.clone(),
            },
            secret_scan::SecretRepresentation {
                class: secret_scan::RepresentationClass::Base64,
                bytes: standard.as_bytes().to_vec(),
            },
            secret_scan::SecretRepresentation {
                class: secret_scan::RepresentationClass::Base64Unpadded,
                bytes: standard.trim_end_matches('=').as_bytes().to_vec(),
            },
            secret_scan::SecretRepresentation {
                class: secret_scan::RepresentationClass::Base64Url,
                bytes: base64::engine::general_purpose::URL_SAFE_NO_PAD
                    .encode(material)
                    .into_bytes(),
            },
            secret_scan::SecretRepresentation {
                class: secret_scan::RepresentationClass::LowerHex,
                bytes: hex::encode(material).into_bytes(),
            },
            secret_scan::SecretRepresentation {
                class: secret_scan::RepresentationClass::UpperHex,
                bytes: hex::encode_upper(material).into_bytes(),
            },
        ]);
    }
    representations
}

fn assert_absent(kind: &str, bytes: &[u8], scanner: &secret_scan::SecretScanner) {
    secret_scan::assert_reader_absent(scanner, kind, std::io::Cursor::new(bytes));
}

fn assert_tree_absent(sink: &str, root: &std::path::Path, scanner: &secret_scan::SecretScanner) {
    let mut pending = vec![root.to_path_buf()];
    while let Some(path) = pending.pop() {
        if path.is_dir() {
            pending.extend(
                std::fs::read_dir(&path)
                    .expect("read audited directory")
                    .map(|entry| entry.expect("audited entry").path()),
            );
        } else if path.is_file() {
            secret_scan::assert_file_absent(scanner, sink, &path);
        }
    }
}

fn assert_tracked_fixtures_absent(scanner: &secret_scan::SecretScanner) {
    let repository = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(std::path::Path::parent)
        .expect("workspace root");
    let tracked = std::process::Command::new("git")
        .args(["ls-files", "-z"])
        .current_dir(repository)
        .output()
        .expect("list tracked fixtures");
    assert!(tracked.status.success());
    for relative in tracked.stdout.split(|byte| *byte == 0) {
        if relative.is_empty() {
            continue;
        }
        let path = repository.join(String::from_utf8_lossy(relative).as_ref());
        if path.is_file() {
            secret_scan::assert_file_absent(scanner, "tracked fixture", &path);
        }
    }
}

#[test]
fn early_child_exit_closes_the_inherited_channel_without_readiness_timeout() {
    let executable = owner_private::ControlledExecutable::copy_from("/usr/bin/false");
    assert!(
        executable.path().is_file(),
        "direct-exec false fixture is required"
    );
    let temporary = owner_private::tempdir();
    let spec = ProtectedBundledRuntimeLaunchSpec::new(
        executable.path(),
        &temporary.path().join("runtime"),
    )
    .expect("early-exit launch spec");
    let started = Instant::now();
    assert_eq!(
        DevelopmentBundledRuntimeLauncher::new()
            .launch(&spec)
            .expect_err("early child exit must close the protected channel"),
        ProtectedBundledRuntimeError::ProtectedChannelUnavailable
    );
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "an exited child must not be reported as a readiness timeout"
    );
}
