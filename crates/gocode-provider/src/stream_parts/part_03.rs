fn validate_event_kind(kind: &ProviderStreamEventKind) -> Result<(), StreamError> {
    match kind {
        ProviderStreamEventKind::TextDelta { text } => {
            validate_payload_bytes(text, MAX_PROVIDER_TEXT_DELTA_BYTES, false)
        }
        ProviderStreamEventKind::ScannerCompleted { text, .. } => {
            validate_payload_bytes(text, MAX_PROVIDER_TEXT_DELTA_BYTES, true)
        }
        ProviderStreamEventKind::ToolCallRequested {
            call_id,
            tool_name,
            arguments_json,
        } => {
            for identifier in [call_id, tool_name] {
                validate_payload_bytes(identifier, MAX_PROVIDER_TOOL_IDENTIFIER_BYTES, false)?;
                if !identifier.bytes().all(|byte| byte.is_ascii_graphic()) {
                    return Err(StreamError::InvalidToolIdentifier);
                }
            }
            validate_payload_bytes(arguments_json, MAX_PROVIDER_TOOL_ARGUMENT_BYTES, false)?;
            serde_json::from_str::<serde_json::Value>(arguments_json)
                .map_err(|_| StreamError::InvalidToolArguments)?;
            Ok(())
        }
        ProviderStreamEventKind::Started
        | ProviderStreamEventKind::Usage { .. }
        | ProviderStreamEventKind::UsageUnavailable
        | ProviderStreamEventKind::ScannerProgress
        | ProviderStreamEventKind::Finished { .. } => Ok(()),
    }
}

fn validate_payload_bytes(value: &str, max: usize, allow_empty: bool) -> Result<(), StreamError> {
    if !allow_empty && value.is_empty() {
        return Err(StreamError::EmptyPayload);
    }
    if value.len() > max {
        return Err(StreamError::PayloadTooLarge {
            max,
            actual: value.len(),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validator_fails_closed_when_sequence_space_is_exhausted() {
        let mut validator = ProviderStreamValidator {
            next_sequence: u64::MAX,
            started: true,
            usage_seen: false,
            terminal: false,
        };
        let event = ProviderStreamEvent::new(
            u64::MAX,
            ProviderStreamEventKind::TextDelta {
                text: "bounded".to_owned(),
            },
        )
        .unwrap();

        assert_eq!(validator.accept(&event), Err(StreamError::SequenceOverflow));
    }
}
