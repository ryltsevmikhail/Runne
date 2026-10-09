#[path = "support/online_credential_fixture.rs"]
mod online_credential_fixture;
#[path = "support/online_proof.rs"]
mod online_proof;
#[path = "support/online_stream_fixture.rs"]
mod online_stream_fixture;
#[path = "support/validated_reopen.rs"]
mod validated_reopen;

mod project_workspace_sqlite {
    mod assignment;
    mod assignment_cancelled;
    mod claim;
    mod claim_event_integrity;
    mod claim_failures;
    mod claimed_text_authority_scope;
    mod claimed_text_taskrun;
    mod command_id;
    mod d2_failure_recovery;
    mod d2_tool_loop_cancellation;
    mod durability;
    mod execution_input;
    mod execution_input_submit_origin;
    mod fence;
    mod history;
    mod integrity;
    mod legacy_local_command_fixture;
    mod local_command_effects_proof;
    mod local_command_lifecycle;
    mod local_command_outcome_unknown;
    mod local_command_preintent_no_effect;
    mod local_command_terminal_guard;
    mod no_effect_release;
    mod origin_mutations;
    mod origin_race;
    mod provider_binding;
    mod race;
    mod rename;
    mod submit_conversation_binding;
    mod submit_fence;
    mod support;
    mod taskrun_claimed_cancellation;
    mod taskrun_legacy_cancellation;
    mod taskrun_queue_scan;
    mod taskrun_tool_budget;
    mod taskrun_tool_invocation_positive;
    mod text_fence;
    mod unknown_successor;
    mod workspace_snapshot;
}
