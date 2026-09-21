//! NM-10 SCAN harness scenario: a trusted admitted root over a hostile
//! workspace holding every frozen canary, driven through the full reachable
//! gateway cycle, with per-sink scans under the frozen rule set.
//!
//! Precondition (S7): the fake env secrets FAKE-SECRET-003/006 are registered
//! into the test secret registry through the existing `SecretBroker` path, so
//! the scans exercise the live secret-exclusion mechanism. Real environment
//! variables are never set or read (`real_env_policy`).

use std::path::Path;
use std::sync::Arc;

use runne_api::{WorkspaceChangeListRequest, WorkspaceDiffReadRequest};
use runne_application::ports::RuntimeAuthorityId;
use runne_application::prohibited_content::ProhibitedContentPort;
use runne_daemon::application::root_admission_authority_fixture::RootAdmissionAuthorityFixture;
use runne_security::SecretBroker;
use runne_security::project_trust_policy::ProjectTrustPolicyAuthority;
use runne_store::ProjectTrustStore;
use runne_store::store::StoreTransaction;

use super::harness::*;
use super::nm10_rules::{
    FAKE_SECRET_API_KEY, FAKE_SECRET_BEARER, FAKE_SECRET_BLOB, FAKE_SECRET_CRASH, FAKE_SECRET_ENV,
    FAKE_SECRET_HEADER, FAKE_SECRET_PEM, PROJ_FILE, PROJ_HELPER, PROJ_HOOK, PROJ_INSTRUCTION,
    PROJ_MANAGED_DENY, PROJ_MCP, PROJ_SKILL, PROJ_UNICODE_NFC, PROJ_UNICODE_NFD, SecretScanner,
    assert_constants_match_frozen_fixtures, project_patterns, scan_absent, scanner,
    secret_patterns,
};
use super::{list, read};

/// S7: register the fake env secrets into the test secret registry through
/// the production broker path before any scenario runs.
fn registered_secret_guard() -> Arc<dyn ProhibitedContentPort> {
    let mut broker = SecretBroker::new();
    broker
        .register(
            "RUNNE_T1_FAKE_SECRET_ENV",
            FAKE_SECRET_ENV.as_bytes().to_vec(),
        )
        .expect("register FAKE-SECRET-003");
    broker
        .register(
            "RUNNE_T1_FAKE_CRASH_REPORT_VAR",
            FAKE_SECRET_CRASH.as_bytes().to_vec(),
        )
        .expect("register FAKE-SECRET-006");
    Arc::new(broker.prohibited_content_guard())
}

fn store_with_registered_secrets() -> (tempfile::TempDir, std::path::PathBuf, StoreTransaction) {
    let directory = tempfile::tempdir().expect("directory");
    let daemon = directory.path().join("runne-daemon");
    std::fs::create_dir_all(&daemon).expect("database layout");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&daemon, std::fs::Permissions::from_mode(0o700))
            .expect("daemon permissions");
    }
    let path = daemon.join("trust-scan.sqlite");
    let store = StoreTransaction::open(
        path.to_str().expect("database path"),
        RuntimeAuthorityId(AUTHORITY_NAME.into()),
        registered_secret_guard(),
    )
    .expect("store");
    (directory, path, store)
}

fn trust_composition_registered(
    canonical: &Path,
) -> (Arc<ProjectTrustStore>, Arc<ProjectTrustPolicyAuthority>) {
    let store = Arc::new(ProjectTrustStore::open(canonical, SIDECAR_AUTHORITY).expect("sidecar"));
    let authority = Arc::new(
        ProjectTrustPolicyAuthority::new(store.clone())
            .with_byte_inspection(registered_secret_guard()),
    );
    (store, authority)
}

/// Hostile workspace: every frozen canary planted in its channel. Secret
/// material lives only under frozen-deny names; the file-channel marker lives
/// in the one readable control file.
fn seed_hostile_workspace(directory: &tempfile::TempDir) {
    let root = directory.path();
    for dir in [
        "notes",
        "keys",
        "instructions",
        "skills",
        "hooks",
        "helpers",
        ".aws",
    ] {
        std::fs::create_dir_all(root.join(dir)).expect("fixture dir");
    }
    let write = |relative: &str, body: String| {
        std::fs::write(root.join(relative), body).expect("fixture file");
    };
    write(
        ".env",
        format!(
            "TOKEN={CANARY}\nRUNNE_T1_FAKE_SECRET_ENV={FAKE_SECRET_ENV}\n{PROJ_UNICODE_NFC}\n{PROJ_UNICODE_NFD}\n"
        ),
    );
    write(
        ".aws/config",
        format!("aws_access_key_id={FAKE_SECRET_API_KEY}\n{PROJ_MANAGED_DENY}\n"),
    );
    write(
        ".netrc",
        format!("machine fixture login owner password {FAKE_SECRET_BEARER}\n"),
    );
    write(
        ".npmrc",
        format!("//registry.local/:_authToken={FAKE_SECRET_HEADER}\n"),
    );
    write(
        "credentials.json",
        format!("{{\"token\":\"{FAKE_SECRET_BLOB}\"}}\n"),
    );
    write("id_rsa", format!("{FAKE_SECRET_PEM}\n"));
    write("keys/host.key", format!("{CANARY}\n"));
    write("instructions/runne.md", format!("{PROJ_INSTRUCTION}\n"));
    write("skills/canary.md", format!("{PROJ_SKILL}\n"));
    write("hooks/pre.sh", format!("{PROJ_HOOK}\n"));
    write("helpers/canary.py", format!("{PROJ_HELPER}\n"));
    write(
        ".mcp.json",
        format!(
            "{{\"mcpServers\":{{\"fixture\":{{\"command\":\"helpers/canary.py\",\"marker\":\"{PROJ_MCP}\"}}}}}}\n"
        ),
    );
    write("notes/plan.md", format!("plan {PROJ_FILE}\n"));
    write("README.md", "readme\n".to_owned());
}

fn walk_entry(
    files: &RootAdmissionAuthorityFixture,
    secret_scanner: &SecretScanner,
    project_scanner: &SecretScanner,
    relative: &str,
    depth: u8,
) {
    if depth > 4 {
        return;
    }
    if let Ok(sub) = files.list_files(PRINCIPAL, &list(workspace(), relative)) {
        let names: Vec<String> = sub
            .items()
            .iter()
            .map(|entry| entry.relative_path().to_owned())
            .collect();
        if names != [relative.to_owned()] {
            let rendered = format!("{names:?}");
            let sink = format!("sink:listing:{relative}");
            scan_absent(secret_scanner, &sink, rendered.as_bytes());
            scan_absent(project_scanner, &sink, rendered.as_bytes());
            for name in &names {
                walk_entry(files, secret_scanner, project_scanner, name, depth + 1);
            }
            return;
        }
    }
    match files.read_file(PRINCIPAL, &read(workspace(), relative)) {
        Ok(content) => {
            // Authorized §B delivery: project markers may appear here (the
            // positive control); denied/registered secret material must not.
            let sink = format!("sink:file-read:{relative}");
            scan_absent(secret_scanner, &sink, content.content().as_bytes());
        }
        Err(error) => {
            let rendered = format!("{error:?}");
            let sink = format!("sink:read-denial:{relative}");
            scan_absent(secret_scanner, &sink, rendered.as_bytes());
            scan_absent(project_scanner, &sink, rendered.as_bytes());
        }
    }
}

#[test]
fn nm10_scan_rules_find_no_canary_in_any_reachable_sink() {
    assert_constants_match_frozen_fixtures();
    let (directory, path, store) = store_with_registered_secrets();
    seed_projects(&store);
    seed_hostile_workspace(&directory);
    let (trust_store, authority) = trust_composition_registered(&path);
    let fixture = fixture_with_trust(&store, authority, sessions());
    grant_trusted(&trust_store, project_trust_id(PROJECT));
    bind_active_root(&fixture, &directory, workspace(), real_now());

    let secret_scanner = scanner(&secret_patterns());
    let project_scanner = scanner(&project_patterns());
    // Scanner liveness: the frozen rules flag their own material.
    let live = format!("preamble {FAKE_SECRET_API_KEY} epilogue {PROJ_FILE}");
    let live_match = match secret_scanner.scan_reader(std::io::Cursor::new(live.as_bytes())) {
        Ok(found) => found,
        Err(_) => panic!("live secret-family scan failed"),
    };
    assert!(
        live_match.is_some(),
        "secret-family scan rules must detect their own material"
    );
    let control_match =
        match project_scanner.scan_reader(std::io::Cursor::new(PROJ_FILE.as_bytes())) {
            Ok(found) => found,
            Err(_) => panic!("live project scan failed"),
        };
    assert!(
        control_match.is_some(),
        "project scan rules must detect their own material"
    );

    let files = &fixture;
    let page = files
        .list_files(PRINCIPAL, &list(workspace(), ""))
        .expect("trusted root listing");
    let names: Vec<String> = page
        .items()
        .iter()
        .map(|entry| entry.relative_path().to_owned())
        .collect();
    let rendered = format!("{names:?}");
    scan_absent(&secret_scanner, "sink:root-listing", rendered.as_bytes());
    scan_absent(&project_scanner, "sink:root-listing", rendered.as_bytes());
    for name in &names {
        walk_entry(files, &secret_scanner, &project_scanner, name, 0);
    }

    let diffs = &fixture;
    let changes = diffs
        .list_changes(
            PRINCIPAL,
            &WorkspaceChangeListRequest::new(workspace(), 200).expect("changes"),
        )
        .expect("captured baseline serves changes");
    let rendered = format!("{changes:?}");
    scan_absent(&secret_scanner, "sink:change-list", rendered.as_bytes());
    scan_absent(&project_scanner, "sink:change-list", rendered.as_bytes());

    match diffs.read_diff(
        PRINCIPAL,
        &WorkspaceDiffReadRequest::new(workspace(), "notes/plan.md").expect("diff"),
    ) {
        Ok(diff) => {
            // Diff of a readable file is the owner's authorized review
            // delivery (same §B class as the file read; frozen-deny names are
            // Forbidden here by the diffs_canary slice): the secret family
            // must be absent, project markers may appear.
            let rendered = format!("{diff:?}");
            scan_absent(&secret_scanner, "sink:diff-read", rendered.as_bytes());
        }
        Err(error) => {
            let rendered = format!("{error:?}");
            scan_absent(
                &secret_scanner,
                "sink:diff-read-denial",
                rendered.as_bytes(),
            );
            scan_absent(
                &project_scanner,
                "sink:diff-read-denial",
                rendered.as_bytes(),
            );
        }
    }
}
