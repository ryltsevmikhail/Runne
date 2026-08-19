#[test]
fn app_core_runtime_mutations_exist_only_in_the_dispatch_coordinator() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/lib_parts");
    let mut paths = vec![root.clone()];
    while let Some(path) = paths.pop() {
        for entry in std::fs::read_dir(path).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                paths.push(path);
                continue;
            }
            if path.extension().and_then(|value| value.to_str()) != Some("rs") {
                continue;
            }
            if path
                .file_stem()
                .and_then(|value| value.to_str())
                .is_some_and(|name| name.ends_with("_tests"))
            {
                continue;
            }
            let source = std::fs::read_to_string(&path).unwrap();
            let relative = path.strip_prefix(&root).unwrap();
            for call in [
                ".create_conversation(",
                ".generate_text(",
                ".create_project(",
                ".archive_project(",
                ".delete_project(",
                ".create_workspace(",
                ".bind_workspace_root(",
                ".open_workspace(",
            ] {
                if source.contains(call) {
                    assert!(
                        path.ends_with("mutation_dispatch/send.rs"),
                        "{path:?} contains {call}"
                    );
                }
            }
            if source.contains(".reconcile_command(") {
                assert_eq!(
                    relative,
                    std::path::Path::new("mutation_reconcile/runtime.rs"),
                    "{path:?}"
                );
            }
            if reconciliation_source(relative) {
                for fallback in [".get_project(", ".get_workspace(", ".list_messages("] {
                    assert!(!source.contains(fallback), "{path:?} contains {fallback}");
                }
            }
        }
    }
}

fn reconciliation_source(relative: &std::path::Path) -> bool {
    relative == std::path::Path::new("mutation_reconcile.rs")
        || relative.starts_with(std::path::Path::new("mutation_reconcile"))
}

#[test]
fn reconciliation_fence_recognizes_nested_sources_but_not_similar_paths() {
    assert!(reconciliation_source(std::path::Path::new(
        "mutation_reconcile.rs"
    )));
    assert!(reconciliation_source(std::path::Path::new(
        "mutation_reconcile/runtime.rs"
    )));
    assert!(!reconciliation_source(std::path::Path::new(
        "mutation_reconcile_escape.rs"
    )));
    assert!(!reconciliation_source(std::path::Path::new(
        "mutation_dispatch/send.rs"
    )));
}

#[test]
fn conversation_operations_do_not_refresh_a_live_client_after_dispatch() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/lib_parts");
    for source in [
        "connect.rs",
        "conversation.rs",
        "subscribe.rs",
        "mutation_conversation.rs",
    ] {
        let path = root.join(source);
        let contents = std::fs::read_to_string(&path).expect("conversation source");
        assert!(
            !contents.contains("live_runtime_client()"),
            "{path:?} bypasses the captured RuntimeOperationContext"
        );
    }
}

#[test]
fn tauri_keeps_runtime_mutation_and_client_types_outside_the_host_bridge() {
    let root =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../apps/desktop/src-tauri/src");
    let mut paths = vec![root];
    while let Some(path) = paths.pop() {
        for entry in std::fs::read_dir(path).unwrap() {
            let entry = entry.unwrap();
            let path = entry.path();
            if path.is_dir() {
                paths.push(path);
                continue;
            }
            if path.extension().and_then(|value| value.to_str()) != Some("rs") {
                continue;
            }
            if path
                .file_stem()
                .and_then(|value| value.to_str())
                .is_some_and(|name| name.ends_with("_tests"))
            {
                continue;
            }
            let source = std::fs::read_to_string(&path).unwrap();
            assert!(
                !source.contains("runne_runtime_client"),
                "{path:?} bypasses AppCore"
            );
            for call in [
                ".bind_workspace_root(",
                ".open_workspace(",
                ".create_workspace(",
                ".delete_project(",
                ".archive_project(",
                ".create_project(",
                ".create_conversation(",
                ".generate_text(",
            ] {
                assert!(!source.contains(call), "{path:?} performs {call}");
            }
        }
    }
}
