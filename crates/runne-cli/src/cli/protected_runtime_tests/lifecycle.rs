use super::*;
use runne_runtime_client::{PermissionModeCommandStatusV2, PermissionModeV1};
use std::path::Path;

#[test]
#[expect(
    clippy::too_many_lines,
    reason = "one real subprocess scenario checks crash, reopen, lock, and replacement"
)]
fn protected_cli_real_process_recovery_and_single_owner_lifecycle() {
    let fixture = fixture();
    let (workspace, initial_revision, _) = seed_workspace(&fixture);
    let workspace = workspace.to_string();
    let mut revision = initial_revision;
    let mut last_committed = None;
    let (headless_read, read_result) =
        spawn_headless_entrypoint(&fixture, &status_arguments(&fixture, &workspace));
    let read = result_value(&child_output(headless_read), &read_result);
    assert_eq!(
        read["exitCode"], 0,
        "actual CLI entrypoint reads headlessly"
    );
    let status: serde_json::Value =
        serde_json::from_str(read["stdout"].as_str().expect("JSON status"))
            .expect("headless status JSON");
    assert_eq!(status["ok"], true);
    assert_eq!(status["data"]["authorizationRevision"], initial_revision);

    let unopened_command = runne_runtime_client::CanonicalId::now_v7().to_string();
    let (headless_mutation, mutation_result) = spawn_headless_entrypoint(
        &fixture,
        &command_arguments(
            &fixture,
            &workspace,
            &unopened_command,
            revision,
            "risk_based",
        ),
    );
    let mutation = result_value(&child_output(headless_mutation), &mutation_result);
    assert_ne!(
        mutation["exitCode"], 0,
        "mutation requires the native GTK path when display is unavailable"
    );
    assert!(permission_witnesses(&fixture).is_empty());
    assert_eq!(mock_consent_count(&fixture), 0);

    for (index, mode) in ["risk_based", "full_access", "ask_always"]
        .into_iter()
        .enumerate()
    {
        let before_post = runne_runtime_client::CanonicalId::now_v7().to_string();
        let consent_count = mock_consent_count(&fixture);
        let (interrupted, interrupted_result) = spawn_cli(
            &fixture,
            &command_arguments(&fixture, &workspace, &before_post, revision, mode),
            Some("before_post"),
        );
        let interrupted_pid = interrupted.id();
        let interrupted = wait_barrier(
            interrupted,
            "before_post",
            &fixture.barrier_dir,
            &interrupted_result,
        );
        let witnesses = permission_witnesses(&fixture);
        assert_eq!(witnesses.len(), index * 2 + 1, "one pre-POST witness");
        assert!(
            witnesses
                .iter()
                .any(|witness| witness["commandId"] == before_post)
        );
        let daemon_pid = first_child_pid(interrupted_pid);
        kill_child(interrupted);
        assert_daemon_stops(daemon_pid);

        let (replay, replay_result) = spawn_cli(
            &fixture,
            &command_arguments(&fixture, &workspace, &before_post, revision, mode),
            None,
        );
        let replay = result_value(&child_output(replay), &replay_result);
        let error: serde_json::Value =
            serde_json::from_str(replay["stderr"].as_str().expect("JSON error output"))
                .expect("permission replay error JSON");
        assert_eq!(replay["exitCode"], 5);
        assert_eq!(error["schemaVersion"], 1);
        assert_eq!(error["ok"], false);
        assert_eq!(error["error"]["code"], "permission_command_unknown");
        assert_eq!(
            error["error"]["message"],
            format!("permission_command_unknown command_id={before_post}")
        );
        assert_eq!(mock_consent_count(&fixture), consent_count);

        let committed = runne_runtime_client::CanonicalId::now_v7().to_string();
        let (committing, committing_result) = spawn_cli(
            &fixture,
            &command_arguments(&fixture, &workspace, &committed, revision, mode),
            Some("after_commit"),
        );
        let committing_pid = committing.id();
        let committing = wait_barrier(
            committing,
            "after_commit",
            &fixture.barrier_dir,
            &committing_result,
        );
        assert_eq!(mock_consent_count(&fixture), consent_count + 1);
        let witnesses = permission_witnesses(&fixture);
        assert_eq!(
            witnesses.len(),
            index * 2 + 2,
            "one committed command witness"
        );
        assert!(
            witnesses
                .iter()
                .any(|witness| witness["commandId"] == committed)
        );
        let daemon_pid = first_child_pid(committing_pid);
        kill_child(committing);
        assert_daemon_stops(daemon_pid);

        if index == 0 {
            let (query, query_result) = spawn_headless_entrypoint(
                &fixture,
                &command_status_arguments(&fixture, &workspace, &committed),
            );
            let query = result_value(&child_output(query), &query_result);
            assert_eq!(query["exitCode"], 0, "headless command-status recovery");
            let envelope: serde_json::Value =
                serde_json::from_str(query["stdout"].as_str().expect("JSON command status"))
                    .expect("headless command-status JSON");
            assert_eq!(envelope["ok"], true);
            let mut data = envelope["data"].clone();
            data.as_object_mut()
                .expect("typed command data")
                .remove("nativeActionRequired");
            let status: PermissionModeCommandStatusV2 =
                serde_json::from_value(data).expect("canonical headless command status");
            let receipt = match status {
                PermissionModeCommandStatusV2::Committed { receipt } => receipt,
                other => panic!("expected committed headless status, got {other:?}"),
            };
            assert_eq!(receipt.command_id.to_string(), committed);
            assert_eq!(receipt.authorization_revision, revision + 1);
            assert_eq!(mock_consent_count(&fixture), consent_count + 1);
        }

        let (reopen, reopen_result) = spawn_cli(
            &fixture,
            &command_arguments(&fixture, &workspace, &committed, revision, mode),
            None,
        );
        let reopened = result_value(&child_output(reopen), &reopen_result);
        assert_eq!(reopened["exitCode"], 0, "committed witness reopens");
        let envelope: serde_json::Value =
            serde_json::from_str(reopened["stdout"].as_str().expect("JSON success output"))
                .expect("committed receipt JSON");
        assert_eq!(envelope["schemaVersion"], 1);
        assert_eq!(envelope["ok"], true);
        assert_eq!(envelope["data"]["state"], "committed");
        let mut data = envelope["data"].clone();
        data.as_object_mut()
            .expect("typed command data")
            .remove("nativeActionRequired");
        let status: PermissionModeCommandStatusV2 =
            serde_json::from_value(data).expect("canonical committed command status");
        let receipt = match status {
            PermissionModeCommandStatusV2::Committed { receipt } => receipt,
            other => panic!("expected committed receipt, got {other:?}"),
        };
        let expected_mode = match mode {
            "ask_always" => PermissionModeV1::AskAlways,
            "risk_based" => PermissionModeV1::RiskBased,
            "full_access" => PermissionModeV1::FullAccess,
            _ => unreachable!("closed mode list"),
        };
        assert_eq!(receipt.command_id.to_string(), committed);
        assert_eq!(
            receipt.idempotency_key,
            format!("protected-cli-{committed}")
        );
        assert_eq!(receipt.selected_mode, expected_mode);
        assert_eq!(receipt.authorization_revision, revision + 1);
        assert_eq!(receipt.history.selected_mode, expected_mode);
        assert_eq!(receipt.history.authorization_revision, revision + 1);
        assert_eq!(mock_consent_count(&fixture), consent_count + 1);
        revision += 1;
        last_committed = Some((committed, mode.to_owned(), reopened["stdout"].clone()));
    }

    let (committed, mode, expected_stdout) = last_committed.expect("three mode cases");
    let (normal, normal_result) = spawn_cli(
        &fixture,
        &command_arguments(&fixture, &workspace, &committed, revision - 1, &mode),
        None,
    );
    let normal = result_value(&child_output(normal), &normal_result);
    assert_eq!(normal["exitCode"], 0, "normal reopen succeeds");
    assert_eq!(normal["stdout"], expected_stdout, "same durable receipt");
    assert_eq!(mock_consent_count(&fixture), 3, "no repeat consent");

    let occupying_command = runne_runtime_client::CanonicalId::now_v7().to_string();
    let (owner, owner_result) = spawn_cli(
        &fixture,
        &command_arguments(
            &fixture,
            &workspace,
            &occupying_command,
            revision,
            "risk_based",
        ),
        Some("before_post"),
    );
    let owner_pid = owner.id();
    let owner = wait_barrier(owner, "before_post", &fixture.barrier_dir, &owner_result);
    let owner_daemon = first_child_pid(owner_pid);
    let (challenger, challenger_result) =
        spawn_cli(&fixture, &status_arguments(&fixture, &workspace), None);
    let challenger = result_value(&child_output(challenger), &challenger_result);
    assert_ne!(
        challenger["exitCode"], 0,
        "occupied root cannot be taken over"
    );
    assert!(Path::new(&format!("/proc/{owner_pid}")).exists());
    assert!(Path::new(&format!("/proc/{owner_daemon}")).exists());
    kill_child(owner);
    assert_daemon_stops(owner_daemon);

    let (replacing, result_path) = spawn_cli(
        &fixture,
        &status_arguments(&fixture, &workspace),
        Some("before_start"),
    );
    let replacing = wait_barrier(
        replacing,
        "before_start",
        &fixture.barrier_dir,
        &result_path,
    );
    let saved_daemon = fixture.bundle.join("runned.original");
    std::fs::rename(&fixture.daemon, &saved_daemon).expect("hold measured adjacent daemon");
    std::os::unix::fs::symlink("/usr/bin/false", &fixture.daemon)
        .expect("install adjacent replacement");
    release_barrier(&fixture, "before_start");
    let replaced = result_value(&child_output(replacing), &result_path);
    std::fs::remove_file(&fixture.daemon).expect("remove adjacent replacement");
    std::fs::rename(saved_daemon, &fixture.daemon).expect("restore original daemon");
    assert_ne!(
        replaced["exitCode"], 0,
        "replacement fails closed before daemon use"
    );
    std::fs::remove_dir_all(&fixture.temporary).expect("remove successful temporary fixture");
}
