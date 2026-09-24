//! Published canonical contract identity for `gocode-ui-client/3`.
//!
//! The checked-in `bundle.json` is generated from contract content only.
//! Source revision evidence is deliberately maintained outside this digest.

/// Canonical API profile identifier.
pub const BUNDLE_ID_V3: &str = "gocode-ui-client/3";
pub const BUNDLE_ID: &str = BUNDLE_ID_V3;

include!("bundle_v2.rs");

/// Exact local transport profile described by this contract.
pub const TRANSPORT_PROFILE_ID: &str = "gocode-local-runtime/2";

/// Generator schema version for the content-only bundle manifest.
pub const GENERATOR_SCHEMA_VERSION: u32 = 1;

/// SHA-256 of the exact checked-in `bundle.json` bytes.
///
/// Updated only by the authoritative contract generator.
pub const PUBLISHED_BUNDLE_HASH: &str =
    "4a97008ecd35edd2022816844fc931e893e29835c0bb9e4d8d8cdab70c9259d4";
pub const PUBLISHED_BUNDLE_HASH_V3: &str = PUBLISHED_BUNDLE_HASH;

/// Exact additive command/query and Aggregate replay surface mounted by the
/// current local daemon.
pub const PUBLISHED_RUNTIME_CAPABILITIES: &[&str] = &[
    "conversation.create.v1",
    "conversation.generate_text.v1",
    "conversation.list_messages.v1",
    "task_run.submit.v1",
    "task_run.submit.v2",
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
    "project.rename.v1",
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

/// Exact protected profile that additionally advertises qualified credential
/// enrollment. Selected only after the native release qualification admits it.
pub const ENROLLMENT_QUALIFIED_RUNTIME_CAPABILITIES: &[&str] = &[
    "conversation.create.v1",
    "conversation.generate_text.v1",
    "conversation.list_messages.v1",
    "task_run.submit.v1",
    "task_run.submit.v2",
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
    "project.rename.v1",
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
    "provider.credential-enrollment.v2",
];

/// Exact base profile for external and deterministic daemon modes.
pub const BASE_RUNTIME_CAPABILITIES: &[&str] = &[
    "conversation.create.v1",
    "conversation.generate_text.v1",
    "conversation.list_messages.v1",
    "task_run.submit.v1",
    "task_run.submit.v2",
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
    "project.rename.v1",
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
    "task_run.submit.v1",
    "task_run.submit.v2",
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
    "project.rename.v1",
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
    "provider.credential-enrollment.v2",
];

pub const PUBLISHED_RUNTIME_CAPABILITIES_V3: &[&str] = PUBLISHED_RUNTIME_CAPABILITIES;
pub const ENROLLMENT_QUALIFIED_RUNTIME_CAPABILITIES_V3: &[&str] =
    ENROLLMENT_QUALIFIED_RUNTIME_CAPABILITIES;
pub const BASE_RUNTIME_CAPABILITIES_V3: &[&str] = BASE_RUNTIME_CAPABILITIES;
pub const RUNTIME_CAPABILITY_CATALOG_V3: &[&str] = RUNTIME_CAPABILITY_CATALOG;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unqualified_profile_omits_enrollment_while_catalog_supports_it() {
        let expected = [
            "conversation.create.v1",
            "conversation.generate_text.v1",
            "conversation.list_messages.v1",
            "task_run.submit.v1",
            "task_run.submit.v2",
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
            "project.rename.v1",
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
        assert!(!PUBLISHED_RUNTIME_CAPABILITIES.contains(&"provider.credential-enrollment.v2"));
        assert_eq!(
            RUNTIME_CAPABILITY_CATALOG,
            [&expected[..], &["provider.credential-enrollment.v2"]].concat()
        );
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
