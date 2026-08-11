//! Published canonical contract identity for `gocode-ui-client/1`.
//!
//! The checked-in `bundle.json` is generated from contract content only.
//! Source revision evidence is deliberately maintained outside this digest.

/// Canonical API profile identifier.
pub const BUNDLE_ID: &str = "gocode-ui-client/1";

/// Exact local transport profile described by this contract.
pub const TRANSPORT_PROFILE_ID: &str = "gocode-local-runtime/2";

/// Generator schema version for the content-only bundle manifest.
pub const GENERATOR_SCHEMA_VERSION: u32 = 1;

/// SHA-256 of the exact checked-in `bundle.json` bytes.
///
/// Updated only by the authoritative contract generator.
pub const PUBLISHED_BUNDLE_HASH: &str =
    "11e6a95464a0dde65e2d2d0d338fe79d1cae847275cbbca7a5d2653669ef2fbe";

/// Exact additive command/query and Aggregate replay surface mounted by the
/// current local daemon.
pub const PUBLISHED_RUNTIME_CAPABILITIES: &[&str] = &[
    "conversation.create.v1",
    "conversation.generate_text.v1",
    "conversation.list_messages.v1",
    "replay.aggregate.open.v1",
    "replay.aggregate.read_page.v1",
    "replay.aggregate.acknowledge.v1",
    "replay.aggregate.complete_catch_up.v1",
    "replay.aggregate.continue_live.v1",
    "replay.aggregate.sse.v1",
    "runtime.operational-telemetry.v1",
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
    "replay.aggregate.open.v1",
    "replay.aggregate.read_page.v1",
    "replay.aggregate.acknowledge.v1",
    "replay.aggregate.complete_catch_up.v1",
    "replay.aggregate.continue_live.v1",
    "replay.aggregate.sse.v1",
    "runtime.operational-telemetry.v1",
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn replay_capabilities_are_published_in_catalog_order() {
        let expected = [
            "conversation.create.v1",
            "conversation.generate_text.v1",
            "conversation.list_messages.v1",
            "replay.aggregate.open.v1",
            "replay.aggregate.read_page.v1",
            "replay.aggregate.acknowledge.v1",
            "replay.aggregate.complete_catch_up.v1",
            "replay.aggregate.continue_live.v1",
            "replay.aggregate.sse.v1",
            "runtime.operational-telemetry.v1",
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
