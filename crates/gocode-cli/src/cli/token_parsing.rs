fn peek(arguments: &VecDeque<OsString>) -> Option<&str> {
    arguments.front().and_then(|value| value.to_str())
}

fn expect_token(arguments: &mut VecDeque<OsString>, expected: &str) -> Result<(), CliError> {
    let actual = pop_string(arguments)?;
    if actual == expected {
        Ok(())
    } else {
        Err(CliError::Usage)
    }
}

fn pop_string(arguments: &mut VecDeque<OsString>) -> Result<String, CliError> {
    arguments
        .pop_front()
        .ok_or(CliError::Usage)?
        .into_string()
        .map_err(|_| CliError::Usage)
}

fn expect_end(arguments: &VecDeque<OsString>) -> Result<(), CliError> {
    if arguments.is_empty() {
        Ok(())
    } else {
        Err(CliError::Usage)
    }
}
