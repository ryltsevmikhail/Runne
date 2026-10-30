use super::*;
pub(in crate::application::exec_taskrun_worker::tool_invocation) fn canonical_arguments_for_mode(
    call: &runne_runtime::provider_tool::RuntimeToolCall,
    coding: bool,
) -> Result<(IntegrityDigest, Vec<u8>, IntegrityDigest), ()> {
    if !coding {
        return canonical_tool_arguments(call);
    }
    let value: serde_json::Value = serde_json::from_str(&call.arguments_json).map_err(|_| ())?;
    crate::safe_tool_helper::coding_arguments::parse(&call.tool_name, &value)?;
    let schema = IntegrityDigest::from_bytes(
        Sha256::digest(
            serde_json::to_vec(
                &runne_provider::ProviderToolDeclarationV1::coding_agent_current_platform(),
            )
            .map_err(|_| ())?,
        )
        .into(),
    );
    let arguments = serde_json::to_vec(&value).map_err(|_| ())?;
    let digest = IntegrityDigest::from_bytes(Sha256::digest(&arguments).into());
    Ok((schema, arguments, digest))
}

pub(in crate::application::exec_taskrun_worker::tool_invocation) fn canonical_tool_arguments(
    call: &runne_runtime::provider_tool::RuntimeToolCall,
) -> Result<(IntegrityDigest, Vec<u8>, IntegrityDigest), ()> {
    let declarations = vec![
        runne_provider::ProviderToolDeclarationV1::for_name(
            runne_provider::ProviderToolNameV1::WorkspaceFileRead,
        ),
        runne_provider::ProviderToolDeclarationV1::for_name(
            runne_provider::ProviderToolNameV1::WorkspaceFileCreateNew,
        ),
    ];
    let schema = IntegrityDigest::from_bytes(
        Sha256::digest(serde_json::to_vec(&declarations).map_err(|_| ())?).into(),
    );
    let value: serde_json::Value = serde_json::from_str(&call.arguments_json).map_err(|_| ())?;
    let arguments = serde_json::to_vec(&value).map_err(|_| ())?;
    let digest = IntegrityDigest::from_bytes(Sha256::digest(&arguments).into());
    Ok((schema, arguments, digest))
}
