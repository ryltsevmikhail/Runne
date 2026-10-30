use super::super::super::*;
use super::super::route::ExecutionRoute;
use crate::canonical_provider::projection::project_call;

pub(super) fn project(
    store: &StoreTransaction,
    job: &CanonicalProviderExecutionJob,
    route: &ExecutionRoute<'_>,
    tool_results: Vec<runne_provider::ProviderToolResultV1>,
    call_id: Option<runne_provider::ProviderCallId>,
) -> Result<ProviderCall, CanonicalProviderExecutionError> {
    let mut call = match project_call(
        store,
        job,
        route.profile.as_ref(),
        route.provider_id,
        route.model_id,
        route.model_revision,
    ) {
        Ok(call) => {
            execution_diagnostics::record("provider_projection_ready", true);
            call
        }
        Err(error) => {
            let stage = execution_diagnostics::projection_failure_stage(error);
            execution_diagnostics::record(stage, false);
            return Err(error);
        }
    };
    if !route.tool_mode {
        return Ok(call);
    }
    if let Some(call_id) = call_id {
        call = ProviderCall::new(
            call_id,
            call.model_ref().clone(),
            *call.manifest_digest(),
            call.max_output_tokens(),
            call.extension().clone(),
        )
        .and_then(|rebuilt| rebuilt.with_text_inputs(call.text_inputs().to_vec()))
        .map_err(|_| CanonicalProviderExecutionError::RejectedBeforeEffect)?;
    }
    let call = call
        .with_tool_context(
            if route.profile.profile_id()
                == runne_provider_deepseek::DEEPSEEK_RESPONSES_TOOL_PROFILE_ID
            {
                use runne_provider::ToolProviderProfile;
                super::super::super::deepseek_profile::exact_tool_profile()
                    .map_err(|_| CanonicalProviderExecutionError::RejectedBeforeEffect)?
                    .tool_declarations()
                    .to_vec()
            } else {
                vec![
                    runne_provider::ProviderToolDeclarationV1::for_name(
                        runne_provider::ProviderToolNameV1::WorkspaceFileRead,
                    ),
                    runne_provider::ProviderToolDeclarationV1::for_name(
                        runne_provider::ProviderToolNameV1::WorkspaceFileCreateNew,
                    ),
                ]
            },
            tool_results,
        )
        .map_err(|_| CanonicalProviderExecutionError::RejectedBeforeEffect)?;
    Ok(call.with_required_capabilities(vec![
        runne_provider::ProviderCapability::Streaming,
        runne_provider::ProviderCapability::Tools,
    ]))
}
