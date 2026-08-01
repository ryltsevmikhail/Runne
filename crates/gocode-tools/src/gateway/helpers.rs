
fn exact_invocation_mut<'a>(
    state: &'a mut BTreeMap<String, InvocationState>,
    invocation_id: &str,
    digest: [u8; 32],
) -> Result<&'a mut InvocationState, ToolGatewayError> {
    let invocation = state
        .get_mut(invocation_id)
        .ok_or(ToolGatewayError::ExecutionNotFound)?;
    ensure_digest(invocation, digest)?;
    Ok(invocation)
}

fn ensure_digest(invocation: &InvocationState, digest: [u8; 32]) -> Result<(), ToolGatewayError> {
    if invocation.digest == digest {
        Ok(())
    } else {
        Err(ToolGatewayError::DigestConflict)
    }
}

fn ensure_request(
    invocation: &InvocationState,
    request: &ToolDispatchRequest,
) -> Result<(), ToolGatewayError> {
    ensure_digest(invocation, request.request_digest)?;
    if invocation.binding == request.binding {
        Ok(())
    } else {
        Err(ToolGatewayError::AuthorityBindingConflict)
    }
}

fn ensure_handle(
    invocation: &InvocationState,
    handle: &ToolExecutionHandle,
) -> Result<(), ToolGatewayError> {
    if invocation.handle.as_ref() == Some(handle) {
        Ok(())
    } else {
        Err(ToolGatewayError::ExecutionNotFound)
    }
}
