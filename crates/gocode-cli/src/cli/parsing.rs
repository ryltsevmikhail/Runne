fn parse_create(mut arguments: VecDeque<OsString>) -> Result<ConversationCommand, CliError> {
    if arguments.is_empty() {
        return Ok(ConversationCommand::Create {
            workspace_id: CanonicalId::now_v7(),
        });
    }
    expect_token(&mut arguments, "--workspace-id")?;
    let workspace_id = parse_id(&pop_string(&mut arguments)?)?;
    expect_end(&arguments)?;
    Ok(ConversationCommand::Create { workspace_id })
}

fn parse_send(mut arguments: VecDeque<OsString>) -> Result<ConversationCommand, CliError> {
    expect_token(&mut arguments, "--conversation-id")?;
    let conversation_id = parse_id(&pop_string(&mut arguments)?)?;
    expect_token(&mut arguments, "--expected-version")?;
    let expected_version = pop_string(&mut arguments)?
        .parse()
        .map_err(|_| CliError::Usage)?;
    expect_token(&mut arguments, "--text")?;
    let text = pop_string(&mut arguments)?;
    expect_end(&arguments)?;
    Ok(ConversationCommand::Send {
        conversation_id,
        expected_version,
        text,
    })
}

fn parse_messages(mut arguments: VecDeque<OsString>) -> Result<ConversationCommand, CliError> {
    expect_token(&mut arguments, "--conversation-id")?;
    let conversation_id = parse_id(&pop_string(&mut arguments)?)?;
    expect_end(&arguments)?;
    Ok(ConversationCommand::Messages { conversation_id })
}

fn parse_id(value: &str) -> Result<CanonicalId, CliError> {
    CanonicalId::parse(value).map_err(|_| CliError::Usage)
}
