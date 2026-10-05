pub(crate) fn record(stage: &'static str) {
    #[cfg(feature = "test-support")]
    {
        eprintln!("runne-store-diagnostic stage={stage}");
        write_test_stage(stage);
    }

    #[cfg(not(feature = "test-support"))]
    let _ = stage;
}

#[cfg(feature = "test-support")]
fn write_test_stage(stage: &'static str) {
    const ALLOWED: &[&str] = &[
        "remote.dispatch_lookup",
        "remote.d2_round_chain",
        "remote.dispatch_ambiguous",
        "remote.attempt_read",
        "remote.attempt_missing",
        "remote.attempt_binding",
        "remote.response_binding",
        "remote.submit_origin",
        "remote.expected_identity",
        "remote.fact_authentication",
        "remote.local_disposition",
        "remote.accounting_projection",
        "remote.grant_projection",
        "remote.credential_projection",
        "effects.stream_validation",
        "effects.taskrun_replay",
        "effects.submit_origin",
        "effects.local_row",
        "effects.local_binding",
        "effects.latest_attempt",
        "effects.local_terminal_proof",
        "effects.local_terminal_unproven",
        "effects.local_projection",
        "effects.local_row_optional",
        "effects.unexpected_local_row",
        "effects.remote_snapshot",
        "source.selected_profile",
        "source.claim_source",
        "source.claim_actor",
        "source.begin_source",
        "source.writer_lease",
        "source.applicability",
        "source.existing_pin",
        "restart.binding",
        "restart.live_epoch",
        "restart.taskrun_state",
        "restart.active_attempt",
        "restart.active_cycle",
        "restart.expected_head",
        "restart.profile",
        "restart.claim",
        "restart.budget",
        "restart.effect_rows",
        "restart.dispatch_intent",
    ];
    if !ALLOWED.contains(&stage) {
        return;
    }
    let Some(directory) = std::env::var_os("RUNNE_TEST_D2_PROVIDER_BARRIER_DIR") else {
        return;
    };
    let directory = std::path::Path::new(&directory);
    let Ok(metadata) = std::fs::symlink_metadata(directory) else {
        return;
    };
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        // The diagnostic target must be within the test's owner-private temp directory.
        if !metadata.is_dir()
            || metadata.file_type().is_symlink()
            || metadata.permissions().mode() & 0o077 != 0
        {
            return;
        }
    }
    #[cfg(not(unix))]
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return;
    }
    let path = directory.join(".runne-test-store-diagnostic-stage");
    #[cfg(unix)]
    let options = {
        use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _};
        if let Ok(existing) = std::fs::symlink_metadata(&path)
            && (existing.file_type().is_symlink()
                || !existing.is_file()
                || existing.uid() != metadata.uid()
                || existing.permissions().mode() & 0o077 != 0)
        {
            return;
        }
        let mut options = std::fs::OpenOptions::new();
        options
            .create_new(true)
            .write(true)
            .mode(0o600)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
        options
    };
    #[cfg(not(unix))]
    let mut options = {
        let mut options = std::fs::OpenOptions::new();
        options.create_new(true).write(true);
        options
    };
    if let Ok(mut file) = options.open(path) {
        use std::io::Write as _;
        let _ = writeln!(file, "{stage}");
    }
}

pub(crate) fn on_error<T, E>(stage: &'static str, result: Result<T, E>) -> Result<T, E> {
    if result.is_err() {
        record(stage);
    }
    result
}
