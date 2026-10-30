pub(super) fn record(error: runne_store::store::taskrun_tool_invocation::ToolInvocationStoreError) {
    use runne_store::store::taskrun_tool_invocation::ToolInvocationStoreError as E;
    crate::application::exec_taskrun_worker::provider::d2_stage(match error {
                    E::ProposalConflict(kind) => match kind {
                        runne_store::store::taskrun_tool_invocation::ProposalConflictKind::Binding => "proposal_store_binding_conflict",
                        runne_store::store::taskrun_tool_invocation::ProposalConflictKind::Sources => "proposal_store_sources_conflict",
                        runne_store::store::taskrun_tool_invocation::ProposalConflictKind::DuplicateEffect => "proposal_store_duplicate_effect",
                        runne_store::store::taskrun_tool_invocation::ProposalConflictKind::EffectDigestToolMismatch => "proposal_store_effect_digest_tool_mismatch",
                        runne_store::store::taskrun_tool_invocation::ProposalConflictKind::EffectDigestArgumentsMismatch => "proposal_store_effect_digest_arguments_mismatch",
                        runne_store::store::taskrun_tool_invocation::ProposalConflictKind::EffectDigestTargetMismatch => "proposal_store_effect_digest_target_mismatch",
                        runne_store::store::taskrun_tool_invocation::ProposalConflictKind::EffectDigestRootMismatch => "proposal_store_effect_digest_root_mismatch",
                        runne_store::store::taskrun_tool_invocation::ProposalConflictKind::PayloadNonce => "proposal_store_payload_nonce",
                        runne_store::store::taskrun_tool_invocation::ProposalConflictKind::InsertUnique => "proposal_store_insert_unique",
                        runne_store::store::taskrun_tool_invocation::ProposalConflictKind::InsertCheck => "proposal_store_insert_check",
                        runne_store::store::taskrun_tool_invocation::ProposalConflictKind::InsertForeignKey => "proposal_store_insert_foreign_key",
                        runne_store::store::taskrun_tool_invocation::ProposalConflictKind::InsertOther => "proposal_store_insert_other",
                    },
                    E::Conflict => "proposal_store_conflict",
                    E::StaleVersion => "proposal_store_stale",
                    E::InvalidState => "proposal_store_invalid_state",
                    E::ApprovalDenied => "proposal_store_approval_denied",
                    E::ApprovalExpired => "proposal_store_approval_expired",
                    E::BudgetExhausted => "proposal_store_budget_exhausted",
                    E::Cancelled => "proposal_store_cancelled",
                    E::Uncertain => "proposal_store_uncertain",
                    E::CorruptData => "proposal_store_corrupt",
                    E::Unavailable => "proposal_store_unavailable",
                });
}
