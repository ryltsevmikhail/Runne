pub(crate) const SSE_RESPONSE: &str = concat!(
    "event: response.created\n",
    "data: {\"type\":\"response.created\",\"sequence_number\":0,\"response\":{\"id\":\"resp_fixture\",\"object\":\"response\",\"model\":\"gpt-5.5-2026-04-23\",\"service_tier\":\"default\",\"status\":\"in_progress\",\"output\":[],\"usage\":null,\"background\":false,\"tools\":[]}}\n\n",
    "event: response.in_progress\n",
    "data: {\"type\":\"response.in_progress\",\"sequence_number\":1,\"response\":{\"id\":\"resp_fixture\",\"object\":\"response\",\"model\":\"gpt-5.5-2026-04-23\",\"service_tier\":\"default\",\"status\":\"in_progress\",\"output\":[],\"usage\":null,\"background\":false,\"tools\":[]}}\n\n",
    "event: response.output_item.added\n",
    "data: {\"type\":\"response.output_item.added\",\"sequence_number\":2,\"output_index\":0,\"item\":{\"id\":\"item_fixture\",\"type\":\"message\",\"status\":\"in_progress\",\"role\":\"assistant\",\"content\":[]}}\n\n",
    "event: response.content_part.added\n",
    "data: {\"type\":\"response.content_part.added\",\"sequence_number\":3,\"output_index\":0,\"item_id\":\"item_fixture\",\"content_index\":0,\"part\":{\"type\":\"output_text\",\"text\":\"\",\"annotations\":[]}}\n\n",
    "event: response.output_text.delta\n",
    "data: {\"type\":\"response.output_text.delta\",\"sequence_number\":4,\"item_id\":\"item_fixture\",\"output_index\":0,\"content_index\":0,\"delta\":\"fixture response\"}\n\n",
    "event: response.output_text.done\n",
    "data: {\"type\":\"response.output_text.done\",\"sequence_number\":5,\"item_id\":\"item_fixture\",\"output_index\":0,\"content_index\":0,\"text\":\"fixture response\"}\n\n",
    "event: response.content_part.done\n",
    "data: {\"type\":\"response.content_part.done\",\"sequence_number\":6,\"item_id\":\"item_fixture\",\"output_index\":0,\"content_index\":0,\"part\":{\"type\":\"output_text\",\"text\":\"fixture response\",\"annotations\":[]}}\n\n",
    "event: response.output_item.done\n",
    "data: {\"type\":\"response.output_item.done\",\"sequence_number\":7,\"output_index\":0,\"item\":{\"id\":\"item_fixture\",\"type\":\"message\",\"status\":\"completed\",\"role\":\"assistant\",\"content\":[{\"type\":\"output_text\",\"text\":\"fixture response\",\"annotations\":[]}]}}\n\n",
    "event: response.completed\n",
    "data: {\"type\":\"response.completed\",\"sequence_number\":8,\"response\":{\"id\":\"resp_fixture\",\"object\":\"response\",\"model\":\"gpt-5.5-2026-04-23\",\"service_tier\":\"default\",\"status\":\"completed\",\"output\":[{\"id\":\"item_fixture\",\"type\":\"message\",\"status\":\"completed\",\"role\":\"assistant\",\"content\":[{\"type\":\"output_text\",\"text\":\"fixture response\",\"annotations\":[]}]}],\"usage\":{\"input_tokens\":1,\"input_tokens_details\":{\"cached_tokens\":0},\"output_tokens\":1,\"output_tokens_details\":{\"reasoning_tokens\":0},\"total_tokens\":2},\"background\":false,\"tools\":[]}}\n\n"
);

#[cfg(test)]
mod tests {
    use gocode_provider::{
        ProviderFinishReason, ProviderStreamEvent, ProviderStreamEventKind,
        ProviderTerminalDisposition, ProviderUsage,
    };
    use gocode_provider_openai::OpenAiSseDecoder;

    use super::SSE_RESPONSE;

    #[test]
    fn fixed_response_decodes() {
        let mut decoder = OpenAiSseDecoder::default();
        decoder.push(SSE_RESPONSE.as_bytes()).unwrap();

        assert_eq!(
            decoder.finish().unwrap(),
            vec![
                ProviderStreamEvent::new(0, ProviderStreamEventKind::Started).unwrap(),
                ProviderStreamEvent::new(
                    1,
                    ProviderStreamEventKind::TextDelta {
                        text: "fixture response".to_owned(),
                    },
                )
                .unwrap(),
                ProviderStreamEvent::new(
                    2,
                    ProviderStreamEventKind::Usage {
                        usage: ProviderUsage::new(1, 1, 0, 0).unwrap(),
                    },
                )
                .unwrap(),
                ProviderStreamEvent::new(
                    3,
                    ProviderStreamEventKind::Finished {
                        disposition: ProviderTerminalDisposition::Completed,
                        reason: ProviderFinishReason::Stop,
                    },
                )
                .unwrap(),
            ]
        );
    }
}
