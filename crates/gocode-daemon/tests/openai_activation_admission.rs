#![cfg(unix)]

use std::os::unix::fs::PermissionsExt as _;

use gocode_daemon::application::DaemonApplication;
use gocode_daemon::config::load_config;
use gocode_daemon::error::DaemonError;

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
             profile_id = \"gocode-openai-responses-text/1\"\n\
             profile_digest = \"d3e20934775d9d970350d16b78a1739885c08dd5d3e47b9307233d4dd0fbed80\"\n",
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
