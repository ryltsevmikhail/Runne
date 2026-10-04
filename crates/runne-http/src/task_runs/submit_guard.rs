fn local_command_content_allowed<H>(
    state: &TaskRunHttpState<H>,
    prompt: &str,
    command: Option<&LocalCommandWire>,
) -> bool {
    use runne_application::prohibited_content::{CanonicalContentBoundary, ContentDisposition};
    let Some(guard) = state.prohibited_content.as_ref() else {
        return false;
    };
    let allowed = |bytes: &[u8]| {
        matches!(
            guard.inspect(CanonicalContentBoundary::CanonicalMutation, bytes),
            Ok(ContentDisposition::Allowed { .. })
        )
    };
    if !allowed(prompt.as_bytes()) {
        return false;
    }
    let Some(command) = command else {
        return true;
    };
    let executable = match &command.executable {
        LocalExecutableWire::WorkspaceRelative(value)
        | LocalExecutableWire::SystemProgram(value) => value,
    };
    allowed(executable.as_bytes())
        && allowed(command.cwd.as_bytes())
        && command.argv.iter().all(|value| allowed(value.as_bytes()))
        && command
            .env
            .iter()
            .all(|entry| allowed(entry.key.as_bytes()) && allowed(entry.value.as_bytes()))
}
