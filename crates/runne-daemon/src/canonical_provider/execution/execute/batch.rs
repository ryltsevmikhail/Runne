use super::*;
pub(super) fn from_sources(
    calls: &[runne_runtime::provider_tool::RuntimeToolCall],
    sources: &[runne_store::store::taskrun_tool_invocation::ToolSourceRef],
) -> Result<InternalProviderResult, CanonicalProviderExecutionError> {
    let terminal = sources
        .iter()
        .find(|s| s.event_kind == 5 && s.terminal)
        .ok_or(CanonicalProviderExecutionError::Uncertain)?;
    let mut tool_sources = sources
        .iter()
        .filter(|s| s.event_kind == 4 && !s.terminal)
        .collect::<Vec<_>>();
    tool_sources.sort_by_key(|s| s.sequence);
    if calls.len() != tool_sources.len() || !(2..=16).contains(&calls.len()) {
        return Err(CanonicalProviderExecutionError::Uncertain);
    }
    Ok(InternalProviderResult::ToolRound(
        super::super::D2ProviderRoundOutcome::Batch {
            proposals: calls
                .iter()
                .cloned()
                .zip(tool_sources)
                .map(|(call, source)| (call, vec![source.clone(), terminal.clone()]))
                .collect(),
        },
    ))
}

pub(super) fn single(
    proposal: Option<runne_runtime::provider_tool::RuntimeToolCall>,
    sources: Vec<runne_store::store::taskrun_tool_invocation::ToolSourceRef>,
    artifact: super::super::super::D2ToolTerminalRef,
) -> Result<InternalProviderResult, CanonicalProviderExecutionError> {
    match proposal {
        Some(call) => {
            if !sources.iter().any(|source| source.event_kind == 4)
                || !sources
                    .iter()
                    .any(|source| source.event_kind == 5 && source.terminal)
            {
                return Err(CanonicalProviderExecutionError::Uncertain);
            }
            Ok(InternalProviderResult::ToolRound(
                super::super::D2ProviderRoundOutcome::Proposal { call, sources },
            ))
        }
        None => Ok(InternalProviderResult::ToolRound(
            super::super::D2ProviderRoundOutcome::FinalStop {
                terminal: artifact,
                sources,
            },
        )),
    }
}
