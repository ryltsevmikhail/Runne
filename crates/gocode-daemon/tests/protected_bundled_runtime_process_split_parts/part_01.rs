use std::collections::HashSet;
use std::path::PathBuf;
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

fn random_secret() -> [u8; 32] {
    let mut value = [0_u8; 32];
    while value == [0; 32] {
        OsRng.fill_bytes(&mut value);
    }
    value
}

fn material_representations(materials: &[Vec<u8>]) -> Vec<Vec<u8>> {
    let mut representations = Vec::new();
    for material in materials {
        let standard = base64::engine::general_purpose::STANDARD.encode(material);
        representations.extend([
            material.clone(),
            standard.as_bytes().to_vec(),
            standard.trim_end_matches('=').as_bytes().to_vec(),
            base64::engine::general_purpose::URL_SAFE_NO_PAD
                .encode(material)
                .into_bytes(),
            hex::encode(material).into_bytes(),
            hex::encode_upper(material).into_bytes(),
        ]);
    }
    representations
}

fn assert_absent(kind: &str, bytes: &[u8], representations: &[Vec<u8>]) {
    for representation in representations {
        assert!(
            !bytes
                .windows(representation.len())
                .any(|window| window == representation),
            "{kind} contained protected material"
        );
    }
}

fn assert_tree_absent(root: &std::path::Path, representations: &[Vec<u8>]) {
    let mut pending = vec![root.to_path_buf()];
    while let Some(path) = pending.pop() {
        if path.is_dir() {
            pending.extend(
                std::fs::read_dir(&path)
                    .expect("read audited directory")
                    .map(|entry| entry.expect("audited entry").path()),
            );
        } else if path.is_file() {
            assert_absent(
                path.to_string_lossy().as_ref(),
                &std::fs::read(&path).expect("read audited artifact"),
                representations,
            );
        }
    }
}

fn assert_tracked_fixtures_absent(representations: &[Vec<u8>]) {
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
            assert_absent(
                path.to_string_lossy().as_ref(),
                &std::fs::read(&path).expect("read tracked file"),
                representations,
            );
        }
    }
}

#[test]
fn early_child_exit_closes_the_inherited_channel_without_readiness_timeout() {
    let executable = PathBuf::from("/usr/bin/false");
    assert!(
        executable.is_file(),
        "direct-exec false fixture is required"
    );
    let temporary = tempfile::tempdir().expect("temporary early-exit root");
    let spec =
        ProtectedBundledRuntimeLaunchSpec::new(&executable, &temporary.path().join("runtime"))
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
