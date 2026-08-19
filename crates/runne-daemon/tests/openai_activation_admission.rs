#![cfg(unix)]

use std::os::unix::fs::PermissionsExt as _;

use runne_daemon::application::DaemonApplication;
use runne_daemon::config::load_config;
use runne_daemon::error::DaemonError;

#[tokio::test]
async fn bare_owner_private_openai_snapshot_is_rejected_without_verified_provenance() {
    let temporary = tempfile::tempdir().expect("temporary owner-private config");
    let config_path = temporary.path().join("config.toml");
    std::fs::write(
        &config_path,
        format!(
            "schema_version = 2\ndb_path = {:?}\nreplay_integrity_key_path = {:?}\n\
             http_bind = \"127.0.0.1:0\"\n[provider_activation]\n\
             mode = \"openai_responses_text_v1\"\n\
             profile_id = \"runne-openai-responses-text/1\"\n\
             profile_digest = \"9e04ed0d3cdeb99279433f01dfd44b2b67af80c076c5a63f45437f9880bae27e\"\n",
            temporary.path().join("event-log.db").display().to_string(),
            temporary.path().join("replay-integrity.key").display().to_string(),
        ),
    )
    .expect("write owner-private config");
    std::fs::set_permissions(&config_path, std::fs::Permissions::from_mode(0o600))
        .expect("restrict owner-private config");
    let config = load_config(Some(&config_path)).expect("load selected OpenAI mode");

    assert!(matches!(
        DaemonApplication::start(&config).await,
        Err(DaemonError::Bootstrap(message))
            if message == "verified provider activation provenance is unavailable"
    ));
}
