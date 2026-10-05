use super::Input;

pub(super) fn valid_d2_inputs(input: &[Input]) -> bool {
    let mut message_count = 0usize;
    let mut cursor = 0usize;
    while cursor < input.len() && input[cursor].kind == "message" {
        let message = &input[cursor];
        let expected_role = if message_count.is_multiple_of(2) {
            "user"
        } else {
            "assistant"
        };
        if message.role != expected_role
            || message.content.len() != 1
            || message.call_id.is_some()
            || message.name.is_some()
            || message.arguments.is_some()
            || message.output.is_some()
        {
            return false;
        }
        let content = &message.content[0];
        let expected_kind = if expected_role == "user" {
            "input_text"
        } else {
            "output_text"
        };
        if content.kind != expected_kind || content.text.len() > 8192 {
            return false;
        }
        message_count += 1;
        cursor += 1;
    }
    if message_count == 0 || message_count.is_multiple_of(2) {
        return false;
    }
    if cursor == input.len() {
        return true;
    }
    if input.len() - cursor != 2 {
        return false;
    }
    let call = &input[cursor];
    let output = &input[cursor + 1];
    call.kind == "function_call"
        && output.kind == "function_call_output"
        && call.call_id.as_deref().is_some_and(valid_call_id)
        && call.call_id == output.call_id
        && matches!(
            call.name.as_deref(),
            Some("workspace_file_read" | "workspace_file_create_new")
        )
        && call.arguments.as_ref().is_some_and(|args| {
            args.len() <= 8192 && serde_json::from_str::<serde_json::Value>(args).is_ok()
        })
        && output
            .output
            .as_ref()
            .is_some_and(|text| text.len() <= 8192)
        && call.role.is_empty()
        && call.content.is_empty()
        && output.role.is_empty()
        && output.content.is_empty()
        && call.output.is_none()
        && output.name.is_none()
        && output.arguments.is_none()
}

fn valid_call_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"_-".contains(&byte))
}
