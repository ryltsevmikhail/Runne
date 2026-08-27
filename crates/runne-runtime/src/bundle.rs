//! Published canonical contract identity for `gocode-ui-client/2`.
//!
//! The checked-in `bundle.json` is generated from contract content only.
//! Source revision evidence is deliberately maintained outside this digest.

/// Canonical API profile identifier.
pub const BUNDLE_ID: &str = "gocode-ui-client/2";

/// Exact local transport profile described by this contract.
pub const TRANSPORT_PROFILE_ID: &str = "gocode-local-runtime/2";

/// Generator schema version for the content-only bundle manifest.
pub const GENERATOR_SCHEMA_VERSION: u32 = 1;

/// SHA-256 of the exact checked-in `bundle.json` bytes.
///
/// Updated only by the authoritative contract generator.
pub const PUBLISHED_BUNDLE_HASH: &str =
    "fd83580faa27046b6355996c9b3ba56689f096591b4a03c51fb6f3c6ce5ff220";

/// Exact additive command/query and Aggregate replay surface mounted by the
/// current local daemon.
pub const PUBLISHED_RUNTIME_CAPABILITIES: &[&str] = &[
    "conversation.create.v1",
    "conversation.generate_text.v1",
    "conversation.list_messages.v1",
    "task_run.get.v1",
    "task_run.cancel.v1",
    "replay.aggregate.open.v1",
    "replay.aggregate.retention_baseline.v1",
    "replay.aggregate.retention_baseline_resume.v2",
    "replay.aggregate.read_page.v1",
    "replay.aggregate.acknowledge.v1",
    "replay.aggregate.complete_catch_up.v1",
    "replay.aggregate.continue_live.v1",
    "replay.aggregate.sse.v1",
    "runtime.operational-telemetry.v1",
    "approval.control.v1",
    "project.list.v1",
    "project.get.v1",
    "project.create.v1",
    "project.archive.v1",
    "project.restore.v1",
    "project.delete.v1",
    "workspace.list.v1",
    "workspace.get.v1",
    "workspace.create.v1",
    "workspace.open.v1",
    "workspace.bind_root.v3",
    "workspace.files.read.v1",
    "workspace.changes.read.v1",
    "workspace.editor.open.v1",
];

/// Exact base profile for external and deterministic daemon modes.
pub const BASE_RUNTIME_CAPABILITIES: &[&str] = &[
    "conversation.create.v1",
    "conversation.generate_text.v1",
    "conversation.list_messages.v1",
    "task_run.get.v1",
    "task_run.cancel.v1",
    "replay.aggregate.open.v1",
    "replay.aggregate.retention_baseline.v1",
    "replay.aggregate.retention_baseline_resume.v2",
    "replay.aggregate.read_page.v1",
    "replay.aggregate.acknowledge.v1",
    "replay.aggregate.complete_catch_up.v1",
    "replay.aggregate.continue_live.v1",
    "replay.aggregate.sse.v1",
    "runtime.operational-telemetry.v1",
    "approval.control.v1",
    "project.list.v1",
    "project.get.v1",
    "project.create.v1",
    "project.archive.v1",
    "project.restore.v1",
    "project.delete.v1",
    "workspace.list.v1",
    "workspace.get.v1",
    "workspace.create.v1",
    "workspace.open.v1",
];

/// Ordered capability catalog described by the generated API contract.
pub const RUNTIME_CAPABILITY_CATALOG: &[&str] = &[
    "conversation.create.v1",
    "conversation.generate_text.v1",
    "conversation.list_messages.v1",
    "task_run.get.v1",
    "task_run.cancel.v1",
    "replay.aggregate.open.v1",
    "replay.aggregate.retention_baseline.v1",
    "replay.aggregate.retention_baseline_resume.v2",
    "replay.aggregate.read_page.v1",
    "replay.aggregate.acknowledge.v1",
    "replay.aggregate.complete_catch_up.v1",
    "replay.aggregate.continue_live.v1",
    "replay.aggregate.sse.v1",
    "runtime.operational-telemetry.v1",
    "approval.control.v1",
    "project.list.v1",
    "project.get.v1",
    "project.create.v1",
    "project.archive.v1",
    "project.restore.v1",
    "project.delete.v1",
    "workspace.list.v1",
    "workspace.get.v1",
    "workspace.create.v1",
    "workspace.open.v1",
    "workspace.bind_root.v3",
    "workspace.files.read.v1",
    "workspace.changes.read.v1",
    "workspace.editor.open.v1",
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn replay_capabilities_are_published_in_catalog_order() {
        let expected = [
            "conversation.create.v1",
            "conversation.generate_text.v1",
            "conversation.list_messages.v1",
            "task_run.get.v1",
            "task_run.cancel.v1",
            "replay.aggregate.open.v1",
            "replay.aggregate.retention_baseline.v1",
            "replay.aggregate.retention_baseline_resume.v2",
            "replay.aggregate.read_page.v1",
            "replay.aggregate.acknowledge.v1",
            "replay.aggregate.complete_catch_up.v1",
            "replay.aggregate.continue_live.v1",
            "replay.aggregate.sse.v1",
            "runtime.operational-telemetry.v1",
            "approval.control.v1",
            "project.list.v1",
            "project.get.v1",
            "project.create.v1",
            "project.archive.v1",
            "project.restore.v1",
            "project.delete.v1",
            "workspace.list.v1",
            "workspace.get.v1",
            "workspace.create.v1",
            "workspace.open.v1",
            "workspace.bind_root.v3",
            "workspace.files.read.v1",
            "workspace.changes.read.v1",
            "workspace.editor.open.v1",
        ];
        assert_eq!(PUBLISHED_RUNTIME_CAPABILITIES, expected);
        assert_eq!(RUNTIME_CAPABILITY_CATALOG, expected);
    }

    #[test]
    fn published_digest_has_exact_lower_hex_shape() {
        assert_eq!(PUBLISHED_BUNDLE_HASH.len(), 64);
        assert!(
            PUBLISHED_BUNDLE_HASH
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        );
    }
}
