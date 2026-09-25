#[path = "support/online_proof.rs"]
mod online_proof;
#[path = "support/validated_reopen.rs"]
mod validated_reopen;

mod project_workspace_sqlite {
    mod assignment;
    mod assignment_cancelled;
    mod claim;
    mod claim_event_integrity;
    mod claim_failures;
    mod command_id;
    mod durability;
    mod execution_input;
    mod fence;
    mod history;
    mod integrity;
    mod no_effect_release;
    mod origin_mutations;
    mod origin_race;
    mod provider_binding;
    mod race;
    mod rename;
    mod submit_conversation_binding;
    mod submit_fence;
    mod support;
    mod taskrun_queue_scan;
    mod text_fence;
    mod workspace_snapshot;
}
