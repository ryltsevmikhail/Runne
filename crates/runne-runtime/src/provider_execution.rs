//! Runtime-owned encrypted provider stream journal and terminal outbox.
//!
//! Credential-sensitive streams first pass through
//! [`crate::provider_redaction::ProviderRedactionRecovery`].

include!("provider_execution_parts/part_01.rs");
include!("provider_execution_parts/part_02.rs");
include!("provider_execution_parts/part_02_runtime_service.rs");
include!("provider_execution_parts/part_03.rs");
include!("provider_execution_parts/part_28_tool_aware.rs");
include!("provider_execution_parts/part_09.rs");
include!("provider_execution_parts/part_10.rs");
include!("provider_execution_parts/part_04.rs");
include!("provider_execution_parts/part_05.rs");
include!("provider_execution_parts/part_07.rs");
include!("provider_execution_parts/part_06.rs");
include!("provider_execution_parts/part_08.rs");
include!("provider_execution_parts/part_13_remote_recovery.rs");
include!("provider_execution_parts/part_13_context_provider.rs");
include!("provider_execution_parts/part_13_remote_recovery_load.rs");
include!("provider_execution_parts/part_14_remote_terminal_artifact.rs");
include!("provider_execution_parts/part_15_remote_terminal_codec.rs");
include!("provider_execution_parts/part_16_remote_terminal_auth.rs");
include!("provider_execution_parts/part_31_stream_settlement_auth.rs");
include!("provider_execution_parts/part_17_remote_terminal_commit.rs");
include!("provider_execution_parts/part_17_remote_terminal_settlement.rs");
include!("provider_execution_parts/part_18_remote_terminal_digest.rs");
include!("provider_execution_parts/part_19_remote_terminal_no_output.rs");
include!("provider_execution_parts/part_20_unknown_terminal.rs");
include!("provider_execution_parts/part_24_unknown_authorization.rs");
include!("provider_execution_parts/part_21_unknown_auth.rs");
include!("provider_execution_parts/part_26_unknown_mac.rs");
include!("provider_execution_parts/part_25_unknown_journal.rs");
include!("provider_execution_parts/part_22_terminal_assembly.rs");
include!("provider_execution_parts/part_23_unknown_commit.rs");
include!("provider_execution_parts/part_27_unknown_effect_auth.rs");
include!("provider_execution_parts/part_29_tool_payload.rs");
include!("provider_execution_parts/part_30_tool_stop_recovery.rs");
#[cfg(test)]
#[path = "provider_execution_parts/part_13_remote_recovery_tests.rs"]
mod remote_recovery_tests;
