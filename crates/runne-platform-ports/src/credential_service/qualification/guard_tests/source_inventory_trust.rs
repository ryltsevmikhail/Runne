pub(super) fn is_trusted_macro_package(name: &str) -> bool {
    matches!(
        name,
        "anyhow"
            | "async-stream"
            | "log"
            | "objc2"
            | "rusqlite"
            | "rustix"
            | "serde"
            | "serde_json"
            | "static_assertions"
            | "tauri"
            | "thiserror"
            | "tokio"
            | "tracing"
    )
}
