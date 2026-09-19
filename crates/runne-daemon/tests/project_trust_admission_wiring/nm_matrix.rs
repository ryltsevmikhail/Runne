//! T1 negative-matrix wiring slice: the hostile-workspace scenarios from
//! `docs/golden/t1/hostile-workspace-negative-matrix-v1.json` that the
//! gateway proves at runtime. NM-05 and NM-09 are covered structurally (the
//! gate submits a runtime-owned constant permission mode and accepts no
//! client trust input — see `trust_tokens.rs` and the policy unit tests);
//! NM-11 is proven by the runne-runtime MCP supervision tests.

use runne_api::{WorkspaceChangeListRequest, WorkspaceDiffReadRequest};

use super::harness::*;
use super::{list, read};

#[test]
fn nm02_post_admission_replacement_stays_contained() {
    let (directory, path, store) = store();
    seed_projects(&store);
    seed_workspace_files(&directory);
    let (trust_store, authority) = trust_composition(&path);
    let fixture = fixture_with_trust(&store, authority, sessions());
    bind_active_root(&fixture, &directory, workspace(), real_now());
    grant_trusted(&trust_store, project_trust_id(PROJECT));
    fixture
        .read_file(PRINCIPAL, &read(workspace(), "notes/plan.md"))
        .expect("admitted read before the hostile swap");

    // Hostile rename/replace between admissions: the admitted path now
    // resolves to a symlink pointing outside the root. The broker re-verifies
    // per open (O_NOFOLLOW per component), so the outside canary stays
    // unreachable through the admitted name.
    let outside = tempfile::tempdir().expect("outside dir");
    let outside_secret = outside.path().join("outside-secret.txt");
    std::fs::write(&outside_secret, format!("OUTSIDE {CANARY}\n")).expect("outside canary");
    std::fs::rename(
        directory.path().join("notes/plan.md"),
        directory.path().join("notes/plan.moved"),
    )
    .expect("hostile rename");
    std::os::unix::fs::symlink(&outside_secret, directory.path().join("notes/plan.md"))
        .expect("hostile symlink swap");

    let error = fixture
        .read_file(PRINCIPAL, &read(workspace(), "notes/plan.md"))
        .expect_err("the swapped path must not serve content");
    assert!(
        !format!("{error:?}").contains(CANARY),
        "outside canary leaked through an admission-passed name: {error:?}"
    );
}

#[test]
fn nm03_case_and_normalization_deny_variants_are_rejected() {
    let (directory, path, store) = store();
    seed_projects(&store);
    seed_workspace_files(&directory);
    let (trust_store, authority) = trust_composition(&path);
    let fixture = fixture_with_trust(&store, authority, sessions());
    bind_active_root(&fixture, &directory, workspace(), real_now());
    grant_trusted(&trust_store, project_trust_id(PROJECT));

    let files = &fixture;
    for variant in [
        ".ENV",
        ".Env",
        ".GIT/config",
        "CONFIG/.SSH/known_hosts",
        "ID_RSA",
        "Credentials.JSON",
        "secret.Key",
        "CERT.Pem",
        "archive.GPG",
    ] {
        let error = files
            .read_file(PRINCIPAL, &read(workspace(), variant))
            .err()
            .unwrap_or_else(|| panic!("{variant} must stay denied"));
        assert!(
            matches!(error, runne_api::WorkspaceFileHostError::Forbidden),
            "{variant}: {error:?}"
        );
    }

    // Trailing-dot forms are distinct names on the supported platforms, not a
    // deny bypass (inventory §G3/R3: extending the set requires a new policy
    // revision). The real `.env` stays denied either way.
    std::fs::write(directory.path().join(".env."), "distinct\n").expect("distinct name file");
    files
        .read_file(PRINCIPAL, &read(workspace(), ".env"))
        .expect_err("the literal denied name is never served");
}

#[test]
fn nm06_revoke_denies_the_captured_baseline_and_masks_block_diffs() {
    let (directory, path, store) = store();
    seed_projects(&store);
    seed_workspace_files(&directory);
    let (trust_store, authority) = trust_composition(&path);
    let fixture = fixture_with_trust(&store, authority, sessions());
    bind_active_root(&fixture, &directory, workspace(), real_now());
    let granted = grant_trusted(&trust_store, project_trust_id(PROJECT));
    bind_active_root(&fixture, &directory, workspace(), real_now());
    let diffs = &fixture;
    let changes = || {
        diffs.list_changes(
            PRINCIPAL,
            &WorkspaceChangeListRequest::new(workspace(), 200).expect("changes"),
        )
    };
    changes().expect("captured baseline serves diffs while trusted");

    // NM-06: the stale baseline copy must not stay reachable once the
    // durable trust state denies the project.
    let revoked = commit_status(
        &trust_store,
        project_trust_id(PROJECT),
        runne_application::project_trust::ProjectTrustStatus::Untrusted,
        granted.managed_deny_mask,
        granted.token(),
    );
    let error = changes().expect_err("revocation denies the captured baseline");
    assert!(
        matches!(error, runne_api::WorkspaceDiffHostError::Forbidden),
        "{error:?}"
    );
    let error = diffs
        .read_diff(
            PRINCIPAL,
            &WorkspaceDiffReadRequest::new(workspace(), "notes/plan.md").expect("diff"),
        )
        .expect_err("stale copy is not delivered through a diff read");
    assert!(
        matches!(error, runne_api::WorkspaceDiffHostError::Forbidden),
        "{error:?}"
    );

    // A managed mask on one channel blocks only that channel, and clearing
    // it re-admits without any new capture.
    let masked = commit_status(
        &trust_store,
        project_trust_id(PROJECT),
        runne_application::project_trust::ProjectTrustStatus::Trusted,
        runne_application::project_trust::SourceChannel::FilesRead.mask_bit(),
        revoked.token(),
    );
    let error = diffs
        .read_diff(
            PRINCIPAL,
            &WorkspaceDiffReadRequest::new(workspace(), "notes/plan.md").expect("diff"),
        )
        .expect_err("the masked read channel blocks diff reads");
    assert!(
        matches!(error, runne_api::WorkspaceDiffHostError::Forbidden),
        "{error:?}"
    );
    changes().expect("the listing channel is not masked");
    commit_status(
        &trust_store,
        project_trust_id(PROJECT),
        runne_application::project_trust::ProjectTrustStatus::Trusted,
        0,
        masked.token(),
    );
    diffs
        .read_diff(
            PRINCIPAL,
            &WorkspaceDiffReadRequest::new(workspace(), "notes/plan.md").expect("diff"),
        )
        .expect("clearing the mask re-admits diff reads");
}

#[test]
fn nm10_secret_canaries_never_reach_any_gateway_sink() {
    let (directory, path, store) = store();
    seed_projects(&store);
    seed_workspace_files(&directory);
    let (trust_store, authority) = trust_composition(&path);
    let fixture = fixture_with_trust(&store, authority, sessions());
    bind_active_root(&fixture, &directory, workspace(), real_now());
    grant_trusted(&trust_store, project_trust_id(PROJECT));

    // Extra secret canaries under frozen-deny names; each has a marker that
    // must never appear in any gateway output.
    std::fs::create_dir_all(directory.path().join(".aws")).expect("aws dir");
    std::fs::write(
        directory.path().join(".aws/config"),
        "AWS_KEY=RUNNE_T1_FAKE_AWS_qz72\n",
    )
    .expect("aws canary");
    std::fs::write(
        directory.path().join("credentials.json"),
        "{\"token\":\"RUNNE_T1_FAKE_CRED_qz73\"}\n",
    )
    .expect("credentials canary");

    let mut sinks = String::new();
    let files = &fixture;
    let page = files
        .list_files(PRINCIPAL, &list(workspace(), ""))
        .expect("trusted root listing");
    let names: Vec<String> = page
        .items()
        .iter()
        .map(|entry| entry.relative_path().to_owned())
        .collect();
    sinks.push_str(&format!("{names:?}"));
    for name in &names {
        if let Ok(content) = files.read_file(PRINCIPAL, &read(workspace(), name)) {
            sinks.push_str(content.content());
        }
    }
    let diffs = &fixture;
    if let Ok(changes) = diffs.list_changes(
        PRINCIPAL,
        &WorkspaceChangeListRequest::new(workspace(), 200).expect("changes"),
    ) {
        sinks.push_str(&format!("{changes:?}"));
    }
    if let Ok(diff) = diffs.read_diff(
        PRINCIPAL,
        &WorkspaceDiffReadRequest::new(workspace(), "notes/plan.md").expect("diff"),
    ) {
        sinks.push_str(&format!("{diff:?}"));
    }

    for marker in [
        "RUNNE_T1_FAKE_AWS_qz72",
        "RUNNE_T1_FAKE_CRED_qz73",
        "TOKEN=RUNNE_T1_FAKE_CANARY_zq71",
    ] {
        assert!(
            !sinks.contains(marker),
            "secret canary {marker} reached a gateway sink"
        );
    }
    // The one authorized delivery is the direct read of the owner's own
    // non-secret file; listings and diffs never carry it.
    assert!(!names.iter().any(|name| name.starts_with('.')), "{names:?}");
}

/// NM-03 revision 2: Unicode case-mapped collision forms of deny names are
/// denied at the gateway admission on a trusted project — the file is never
/// read even though it does not byte-equal the frozen name (NT UPCATE maps
/// U+0131 to ASCII I, so a case-insensitive platform would open `id_rsa`).
#[test]
fn nm03_unicode_case_mapped_deny_forms_stay_denied() {
    let (directory, path, store) = store();
    seed_projects(&store);
    seed_workspace_files(&directory);
    let (trust_store, authority) = trust_composition(&path);
    let fixture = fixture_with_trust(&store, authority, sessions());
    bind_active_root(&fixture, &directory, workspace(), real_now());
    grant_trusted(&trust_store, project_trust_id(PROJECT));

    std::fs::write(
        directory.path().join("ıd_rsa"),
        "RUNNE_T1_FAKE_CANARY_zq71\n",
    )
    .expect("homoglyph key fixture");

    let files = &fixture;
    let error = files
        .read_file(PRINCIPAL, &read(workspace(), "ıd_rsa"))
        .expect_err("case-mapped deny form must stay denied");
    assert!(
        !format!("{error:?}").contains("RUNNE_T1_FAKE_CANARY_zq71"),
        "no canary text in the denial"
    );

    // The exact ASCII name stays denied as before, and the policy revision is
    // what the admission carries.
    let error = files
        .read_file(PRINCIPAL, &read(workspace(), "id_rsa"))
        .expect_err("exact deny name stays denied");
    assert!(matches!(
        error,
        runne_api::WorkspaceFileHostError::Forbidden
    ));
}
