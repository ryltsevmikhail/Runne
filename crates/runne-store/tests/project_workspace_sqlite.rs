#[path = "support/validated_reopen.rs"]
mod validated_reopen;

mod project_workspace_sqlite {
    mod claim;
    mod claim_event_integrity;
    mod claim_failures;
    mod command_id;
    mod durability;
    mod fence;
    mod history;
    mod integrity;
    mod origin_mutations;
    mod origin_race;
    mod race;
    mod rename;
    mod submit_conversation_binding;
    mod submit_fence;
    mod support;
    mod text_fence;
    mod workspace_snapshot;
}
