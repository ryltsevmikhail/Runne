//! Table test for the closed config-problem classification of `runned doctor`.
//!
//! Every static message of the config layer reachable from `run_doctor` is
//! pinned as a contract: exact text → stable `[config.*]` id, with the exact
//! text preserved as the (safe) reason. Synthetic leak strings prove that toml
//! snippets, schema values and raw io text never reach `render()`. Only
//! synthetic `DaemonError` values are used — no filesystem, no host state.

use super::config_problem::{ConfigProblem, classify_config_error};
use crate::error::{
    DaemonError, RuntimeStoreOpenRejection, RuntimeStoreOpenStage, RuntimeStoreRejection,
};
use runne_store::schema::recovery_diagnosis::StoreRecoveryDiagnosis;

const TOKEN_CANARY: &str = "sk-synthetic-abc123";
const PATH_CANARY: &str = "/home/synthetic/private/config.toml";
const FIELD_CANARY: &str = "synthetic_not_a_token";

/// The full static inventory reachable from `run_doctor`: (exact message,
/// expected id). 26 entries — 4 dedicated load ids + 22 validation literals
/// under `config.activation` (load.rs, merge.rs, provider_settings.rs,
/// `validate_settings`).
const STATIC_INVENTORY: &[(&str, &str)] = &[
    (
        "external config is not owner-private",
        "config.not_owner_private",
    ),
    ("external config exceeds size limit", "config.too_large"),
    ("external config is not UTF-8", "config.not_utf8"),
    (
        "external config validation is unsupported",
        "config.unsupported_platform",
    ),
    ("invalid provider activation mode", "config.activation"),
    ("invalid provider activation digest", "config.activation"),
    ("Responses profile digest mismatch", "config.activation"),
    ("invalid provider activation profile", "config.activation"),
    ("Radius catalog snapshot is required", "config.activation"),
    ("Radius catalog snapshot is invalid", "config.activation"),
    ("Radius model is required", "config.activation"),
    ("Radius catalog revision is required", "config.activation"),
    (
        "token-plan accounting is not valid for Radius",
        "config.activation",
    ),
    (
        "Radius model is not in the bound catalog",
        "config.activation",
    ),
    ("invalid provider pricing digest", "config.activation"),
    ("invalid provider accounting mode", "config.activation"),
    (
        "Radius settings are not valid for native provider",
        "config.activation",
    ),
    (
        "Vertex settings do not match selected native provider",
        "config.activation",
    ),
    (
        "Vertex accounting mode is fixed by its trusted profile",
        "config.activation",
    ),
    (
        "MiniMax accounting mode must be explicit",
        "config.activation",
    ),
    (
        "Accounting mode is not valid for selected native provider",
        "config.activation",
    ),
    (
        "Radius settings are incomplete or mixed with Vertex settings",
        "config.activation",
    ),
    (
        "Responses settings are mixed with another provider family",
        "config.activation",
    ),
    ("Azure Responses settings are required", "config.activation"),
    (
        "Cloud settings are mixed with another provider family",
        "config.activation",
    ),
    (
        "provider settings are inappropriate for selected mode",
        "config.activation",
    ),
];

fn classify_message(message: &str) -> ConfigProblem {
    classify_config_error(&DaemonError::Config(message.to_owned()))
}

#[test]
fn every_static_config_message_maps_to_its_stable_id() {
    assert_eq!(STATIC_INVENTORY.len(), 26, "full reachable inventory");
    for (message, id) in STATIC_INVENTORY {
        let problem = classify_message(message);
        assert_eq!(problem.id, *id, "message: {message}");
        // The exact static text stays the reason — it is a closed literal
        // with no path or content echo.
        assert_eq!(problem.reason, *message);
        let rendered = problem.render();
        assert!(rendered.contains(&format!("[{id}]")), "{rendered}");
        assert!(rendered.contains(message), "{rendered}");
        assert!(
            !rendered.contains("config error:"),
            "doubled prefix must stay gone: {rendered}"
        );
    }
}

#[test]
fn toml_and_unknown_messages_are_withheld_fail_closed() {
    let toml_like = format!(
        "TOML parse error at line 2, column 1\n  |\n2 | {FIELD_CANARY} = \"{TOKEN_CANARY}\"\n"
    );
    let problem = classify_message(&toml_like);
    assert_eq!(problem.id, "config.parse");
    assert_eq!(problem.reason, "configuration file could not be parsed");
    let rendered = problem.render();
    for leak in [TOKEN_CANARY, FIELD_CANARY, PATH_CANARY, "line 2"] {
        assert!(!rendered.contains(leak), "leak {leak}: {rendered}");
    }

    let unknown = format!("{PATH_CANARY} is unreadable ({TOKEN_CANARY})");
    let problem = classify_message(&unknown);
    assert_eq!(problem.id, "config.invalid");
    assert_eq!(problem.reason, "configuration rejected (cause withheld)");
    let rendered = problem.render();
    for leak in [TOKEN_CANARY, PATH_CANARY] {
        assert!(!rendered.contains(leak), "leak {leak}: {rendered}");
    }
}

#[test]
fn io_errors_carry_only_the_closed_std_kind_name() {
    let permission = std::io::Error::from(std::io::ErrorKind::PermissionDenied);
    let problem = classify_config_error(&DaemonError::Io(permission));
    assert_eq!(problem.id, "config.io_access");
    assert_eq!(problem.reason, "PermissionDenied");
    assert!(problem.render().contains("PermissionDenied"));

    // ELOOP (broken symlink) is classified by errno: `ErrorKind::FilesystemLoop`
    // and `ErrorKind::name()` are unstable on the pinned toolchain.
    let file_system_loop = std::io::Error::from_raw_os_error(libc::ELOOP);
    let problem = classify_config_error(&DaemonError::Io(file_system_loop));
    assert_eq!(problem.id, "config.io_access");
    assert_eq!(problem.reason, "FilesystemLoop");
    let rendered = problem.render();
    assert!(rendered.contains("FilesystemLoop"), "{rendered}");
    assert!(!rendered.contains(PATH_CANARY), "{rendered}");
    assert!(
        !rendered.contains("os error"),
        "raw io text withheld: {rendered}"
    );
}

#[test]
fn schema_value_and_unreachable_variants_stay_closed() {
    let problem = classify_config_error(&DaemonError::Schema(
        "unsupported schema_version: expected 2, got 3".to_owned(),
    ));
    assert_eq!(problem.id, "config.schema_version");
    assert!(!problem.render().contains("got 3"));

    for error in [
        DaemonError::Lock("synthetic lock detail".to_owned()),
        DaemonError::Bootstrap("synthetic bootstrap detail".to_owned()),
        DaemonError::StoreOpenRejection(RuntimeStoreOpenRejection {
            purpose: "synthetic".to_owned(),
            stage: RuntimeStoreOpenStage::Open,
            rejection: RuntimeStoreRejection::Unavailable,
            recovery_state: StoreRecoveryDiagnosis::Ready,
        }),
    ] {
        let problem = classify_config_error(&error);
        assert_eq!(problem.id, "config.invalid");
        assert_eq!(
            problem.reason,
            "configuration state rejected (cause withheld)"
        );
        assert!(!problem.render().contains("synthetic"));
    }
}

#[test]
fn classification_ids_stay_pairwise_distinct() {
    let mut ids: Vec<&str> = STATIC_INVENTORY.iter().map(|(_, id)| *id).collect();
    ids.extend([
        "config.parse",
        "config.invalid",
        "config.io_access",
        "config.schema_version",
    ]);
    ids.sort_unstable();
    ids.dedup();
    assert_eq!(
        ids,
        [
            "config.activation",
            "config.invalid",
            "config.io_access",
            "config.not_owner_private",
            "config.not_utf8",
            "config.parse",
            "config.schema_version",
            "config.too_large",
            "config.unsupported_platform",
        ]
    );
}
