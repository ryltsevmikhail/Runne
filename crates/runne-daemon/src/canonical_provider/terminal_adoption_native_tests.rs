use super::*;
use crate::protected_activation::terminal_adoption as adoption;
use std::{fs, os::unix::fs::PermissionsExt as _, path::Path, process::Command};

#[test]
fn native_external_upgrade_adoption_and_finite_repin_preserve_existing_database() {
    if std::env::var_os("RUNNE_ADOPTION_FIXTURE_CHILD").is_some() {
        child();
        return;
    }
    // Image policy requires owner-controlled ancestors, so do not use /tmp.
    let fixture = tempfile::Builder::new()
        .prefix("adoption-native-")
        .tempdir_in(std::env::current_dir().unwrap())
        .unwrap();
    let root = fixture.path();
    fs::set_permissions(root, fs::Permissions::from_mode(0o700)).unwrap();
    for dir in ["runtime", "config", "config/runne-daemon", "new", "old"] {
        private_dir(&root.join(dir));
    }
    let executable = root.join("new/runned");
    fs::copy(std::env::current_exe().unwrap(), &executable).unwrap();
    fs::set_permissions(&executable, fs::Permissions::from_mode(0o700)).unwrap();
    for (name, value) in [
        ("new/runne", b"synthetic-cli-new".as_slice()),
        (
            "new/runne-credential-host",
            b"synthetic-host-new".as_slice(),
        ),
        ("old/runne", b"synthetic-cli-old".as_slice()),
        ("old/runned", b"synthetic-daemon-old".as_slice()),
        (
            "old/runne-credential-host",
            b"synthetic-host-old".as_slice(),
        ),
    ] {
        fs::write(root.join(name), value).unwrap();
        fs::set_permissions(root.join(name), fs::Permissions::from_mode(0o700)).unwrap();
    }
    let result = Command::new(&executable)
        .args(["--exact", "canonical_provider::terminal_adoption::native_tests::native_external_upgrade_adoption_and_finite_repin_preserve_existing_database", "--nocapture"])
        .env("RUNNE_ADOPTION_FIXTURE_CHILD", root)
        .env("XDG_CONFIG_HOME", root.join("config"))
        .env("XDG_RUNTIME_DIR", root.join("runtime"))
        .output().unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert!(String::from_utf8_lossy(&result.stdout).contains("PASS checked native adoption"));
}

fn private_dir(path: &Path) {
    fs::create_dir(path).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
}
fn write_private(path: &Path, value: &str) {
    fs::write(path, value).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
}
fn config(directory: &Path) -> String {
    let digest = |name| hex::encode(Sha256::digest(fs::read(directory.join(name)).unwrap()));
    format!(
        "schema_version=2\n[provider_activation]\nmode='deepseek_responses_text_v1'\nprofile_id='gocode-deepseek-responses-text/1'\nprofile_digest='0112c4b6ce64739810bb79802ebb5ae6fd8ac563d1d1397ac51f07a190538195'\n[linux_cli_credential_host]\ncli_sha256='{}'\ndaemon_sha256='{}'\nhost_sha256='{}'\n",
        digest("runne"),
        digest("runned"),
        digest("runne-credential-host")
    )
}
fn child() {
    if std::env::var_os("RUNNE_IMAGE_UPGRADE_FIXTURE_CHILD").is_some() {
        image_upgrade_child();
        return;
    }
    let root = std::path::PathBuf::from(std::env::var_os("RUNNE_ADOPTION_FIXTURE_CHILD").unwrap());
    let path = crate::config::external_config_path();
    let old = config(&root.join("old"));
    let next = config(&root.join("new"));
    write_private(&path, &old);
    write_private(&root.join("before.toml"), &old);
    let config = crate::config::load_external_config().unwrap();
    let bootstrap = crate::bootstrap::bootstrap(&config).unwrap();
    assert!(!bootstrap.db_existed);
    let authority = bootstrap.authority_id;
    let local = bootstrap.local_session_authority_id;
    runne_store::schema::ensure_event_log_lineage_id(&bootstrap.db_conn).unwrap();
    let lineage = runne_store::schema::read_event_log_lineage_id(&bootstrap.db_conn).unwrap();
    let profile = SharedTextProviderProfile::new(Arc::new(
        runne_provider_deepseek::DeepSeekResponsesTextProfile::from_json(include_bytes!(
            "../../../../docs/profiles/deepseek-responses-text-v1.json"
        ))
        .unwrap(),
    ));
    let before = runtime_launch::configuration(
        authority,
        bootstrap.launch_generation,
        &DaemonActivationProvenance::for_cli_upgrade(&config, authority),
        &profile,
        "provider.deepseek.responses.text",
    );
    let store =
        SqliteProviderExecutionStore::open_with_connection(&config.db_path, bootstrap.db_conn)
            .unwrap();
    store.activate_runtime_launch(&before).unwrap();
    drop(store);
    drop(bootstrap.locks);
    // Synthetic settled counters prove this transition is not a fresh grant reset.
    let counters = rusqlite::Connection::open(&config.db_path).unwrap();
    counters.execute("UPDATE provider_runtime_authority_state SET token_budget_settled=17,cost_budget_settled_micros=23 WHERE id=1", []).unwrap();
    runne_store::schema::rewind_empty_terminal_schema_for_test(&counters).unwrap();
    assert_eq!(
        counters
            .query_row("SELECT MAX(version) FROM schema_version", [], |r| r
                .get::<_, i64>(0))
            .unwrap(),
        69
    );
    drop(counters);
    let original = durable(&config.db_path);
    write_private(&path, &next);
    crate::linux_cli_credential_host::upgrade::upgrade(
        &root.join("old"),
        &root.join("before.toml"),
    )
    .unwrap();
    assert_eq!(durable(&config.db_path), original);
    // Exact retry must not reset grant expiry or counters.
    crate::linux_cli_credential_host::upgrade::upgrade(
        &root.join("old"),
        &root.join("before.toml"),
    )
    .unwrap();
    let preview = adoption::prepare().unwrap();
    assert!(!preview.already_adopted);
    assert!(adoption::commit(&"0".repeat(64)).is_err());
    adoption::commit(&preview.manifest).unwrap();
    adoption::commit(&preview.manifest).unwrap();
    assert_eq!(durable(&config.db_path), original);
    let conn = runne_store::schema::open_existing_read_only(Path::new(&config.db_path)).unwrap();
    assert_eq!(
        runne_store::schema::read_event_log_lineage_id(&conn).unwrap(),
        lineage
    );
    let kind: String = conn
        .query_row(
            "SELECT activation_binding_kind FROM provider_runtime_authority_state WHERE id=1",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(kind, "protected_v2");
    drop(conn);
    write_private(&root.join("adopted.toml"), &next);
    let finite = format!(
        "{next}\n[d2_safe_tool_loop_budget]\ntoken_budget_limit=1000000\ncost_budget_limit_micros=4000000\n"
    );
    write_private(&path, &finite);
    let preview = adoption::prepare().unwrap();
    assert!(preview.already_adopted);
    assert!(
        runne_platform_desktop::verify_terminal_installation_source(&root.join("runtime"), &path,)
            .is_err(),
        "unrepinned source remains closed"
    );
    adoption::repin_tools(&root.join("adopted.toml"), &preview.manifest).unwrap();
    adoption::repin_tools(&root.join("adopted.toml"), &preview.manifest).unwrap();
    assert_eq!(durable(&config.db_path), original);
    let check =
        crate::bootstrap::bootstrap(&crate::config::load_external_config().unwrap()).unwrap();
    assert!(
        adoption::credential_access(&check.db_conn).is_ok(),
        "repinned exact source restores existing credential policy without reading it"
    );
    assert_eq!(check.authority_id, authority);
    assert_eq!(check.local_session_authority_id, local);
    assert_eq!(
        runne_store::schema::read_event_log_lineage_id(&check.db_conn).unwrap(),
        lineage
    );
    let version: i64 = check
        .db_conn
        .query_row("SELECT MAX(version) FROM schema_version", [], |r| r.get(0))
        .unwrap();
    assert_eq!(version, 71);
    drop(check);
    write_private(&root.join("finite-before.toml"), &finite);
    let newer = root.join("newer");
    private_dir(&newer);
    for name in ["runne", "runned", "runne-credential-host"] {
        fs::copy(root.join("new").join(name), newer.join(name)).unwrap();
    }
    fs::write(newer.join("runne"), b"synthetic-cli-newer").unwrap();
    let upgraded = format!(
        "{}\n[d2_safe_tool_loop_budget]\ntoken_budget_limit=1000000\ncost_budget_limit_micros=4000000\n",
        self::config(&newer)
    );
    write_private(&path, &upgraded);
    let result = Command::new(newer.join("runned"))
        .args(["--exact", "canonical_provider::terminal_adoption::native_tests::native_external_upgrade_adoption_and_finite_repin_preserve_existing_database", "--nocapture"])
        .env("RUNNE_IMAGE_UPGRADE_FIXTURE_CHILD", "1").output().unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert_eq!(durable(&config.db_path), original);
    println!(
        "PASS checked native adoption: exact pins upgrade, manifest consent, protected anchor, finite repin, retries, existing authority/lineage/budgets/expiry preserved"
    );
}
fn durable(path: &str) -> Vec<rusqlite::types::Value> {
    let conn = runne_store::schema::open_existing_read_only(Path::new(path)).unwrap();
    conn.query_row("SELECT runtime_authority_id,database_generation,principal_id,scope,profile_digest,pricing_revision_digest,token_budget_limit,token_budget_settled,token_budget_reserved,cost_budget_limit_micros,cost_budget_settled_micros,cost_budget_reserved_micros,approval_expires_at,(SELECT COUNT(*) FROM events),(SELECT COUNT(*) FROM provider_dispatch_attempts) FROM provider_runtime_authority_state WHERE id=1", [], |r| (0..15).map(|i|r.get(i)).collect()).unwrap()
}

fn image_upgrade_child() {
    let root = std::path::PathBuf::from(std::env::var_os("RUNNE_ADOPTION_FIXTURE_CHILD").unwrap());
    let preview = adoption::prepare().unwrap();
    assert!(preview.already_adopted);
    assert!(
        adoption::upgrade_images(
            &root.join("new"),
            &root.join("finite-before.toml"),
            &"0".repeat(64)
        )
        .is_err()
    );
    for _ in 0..2 {
        adoption::upgrade_images(
            &root.join("new"),
            &root.join("finite-before.toml"),
            &preview.manifest,
        )
        .unwrap();
    }
    let config = crate::config::load_external_config().unwrap();
    let check = crate::bootstrap::bootstrap(&config).unwrap();
    assert!(adoption::credential_access(&check.db_conn).is_ok());
}
