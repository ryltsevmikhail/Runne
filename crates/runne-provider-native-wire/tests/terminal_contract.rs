use runne_provider::{ProviderFinishReason, ProviderStreamEventKind, ProviderTerminalDisposition};
use runne_provider_native_wire::{
    AnthropicMessagesProfile, AnthropicStreamDecoder, AnthropicStreamError, GeminiProfile,
    GeminiStreamDecoder, WireLimits,
};

fn profiles() -> (AnthropicMessagesProfile, GeminiProfile) {
    let limits = WireLimits::new(8, 128, 512, 256, 4096, 2048).unwrap();
    (
        AnthropicMessagesProfile::new(
            "anthropic",
            "anthropic-text/1",
            "claude-native-test",
            "2026-09-14",
            [1; 32],
            [2; 32],
            limits,
        )
        .unwrap(),
        GeminiProfile::new(
            "google",
            "gemini-text/1",
            "gemini-native-test",
            "2026-09-14",
            [3; 32],
            [4; 32],
            limits,
        )
        .unwrap(),
    )
}

#[test]
fn content_filter_is_incomplete_and_usage_overflow_is_rejected() {
    let stream = concat!(
        "data: {\"candidates\":[{\"content\":{\"parts\":[{\"text\":\"x\"}]},\"index\":0}],\"modelVersion\":\"gemini-native-test\"}\n\n",
        "data: {\"candidates\":[{\"content\":{\"parts\":[]},\"finishReason\":\"SAFETY\",\"index\":0}],\"usageMetadata\":{\"promptTokenCount\":1,\"candidatesTokenCount\":1,\"totalTokenCount\":2},\"modelVersion\":\"gemini-native-test\"}\n\n",
    );
    let mut decoder = GeminiStreamDecoder::for_profile(&profiles().1);
    decoder.push(stream.as_bytes()).unwrap();
    let events = decoder.finish().unwrap();
    assert!(matches!(
        events.last().unwrap().kind(),
        ProviderStreamEventKind::Finished {
            disposition: ProviderTerminalDisposition::RemoteIncomplete,
            reason: ProviderFinishReason::ContentFilter
        }
    ));

    let overflow = concat!(
        "event: message_start\n",
        "data: {\"type\":\"message_start\",\"message\":{\"id\":\"x\",\"type\":\"message\",\"role\":\"assistant\",\"model\":\"claude-native-test\",\"usage\":{\"input_tokens\":18446744073709551615,\"cache_read_input_tokens\":1}}}\n\n",
    );
    let mut decoder = AnthropicStreamDecoder::for_profile(&profiles().0);
    assert_eq!(
        decoder.push(overflow.as_bytes()),
        Err(AnthropicStreamError::InvalidUsage)
    );
}
