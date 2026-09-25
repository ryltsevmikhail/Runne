use super::*;

#[test]
fn explicit_accounting_prices_uncached_cached_and_output_separately() {
    let profile = AnthropicMessagesProfile::new_with_accounting(
        "anthropic",
        "anthropic-text/1",
        "claude-native-test",
        "2026-09-14",
        [1; 32],
        [2; 32],
        limits(),
        NativeAccounting::Payg {
            input_micros_per_million: 3_000_000,
            output_micros_per_million: 15_000_000,
            cached_input_micros_per_million: 300_000,
            cache_write_micros_per_million: 0,
        },
    )
    .unwrap();
    let usage = ProviderUsage::new(1_000_001, 2, 1, 0).unwrap();
    let quote = profile
        .price_terminal_usage(&[2; 32], &[1; 32], 0, usage)
        .unwrap();
    assert_eq!(quote.charge_micros(), 3_000_031);
    assert_eq!(quote.currency(), "USD");
    assert_eq!(profile.currency(), "USD");
}

#[test]
fn subscription_accounting_is_explicit_zero_xxx_and_not_payg_free() {
    let profile = AnthropicMessagesProfile::new_with_accounting(
        "kimi-coding",
        "kimi-coding-text/1",
        "k3-256k",
        "2026-09-14",
        [5; 32],
        [6; 32],
        limits(),
        NativeAccounting::SubscriptionQuotaExternallyMetered,
    )
    .unwrap();
    let usage = ProviderUsage::new(1_000_000, 2_000_000, 0, 0).unwrap();
    let quote = profile
        .price_terminal_usage(&[6; 32], &[5; 32], 0, usage)
        .unwrap();
    assert_eq!(quote.charge_micros(), 0);
    assert_eq!(quote.currency(), "XXX");
    assert_eq!(profile.currency(), "XXX");
    assert_eq!(profile.price_usage_micros(usage).unwrap(), 0);
}

#[test]
fn token_plan_accounting_is_distinct_from_payg() {
    let profile = AnthropicMessagesProfile::new_with_accounting(
        "minimax",
        "minimax-text/1",
        "MiniMax-M2.7",
        "2026-09-14",
        [8; 32],
        [9; 32],
        limits(),
        NativeAccounting::TokenPlanQuotaExternallyMetered,
    )
    .unwrap();
    let usage = ProviderUsage::new(10, 20, 0, 0).unwrap();
    let quote = profile
        .price_terminal_usage(&[9; 32], &[8; 32], 0, usage)
        .unwrap();
    assert_eq!(quote.currency(), "XXX");
    assert_eq!(quote.charge_micros(), 0);
}

#[test]
fn decoders_reject_truncated_malformed_oversize_duplicate_and_unsupported_frames() {
    let valid = include_bytes!("../fixtures/gemini_stream.sse");
    let mut truncated = GeminiStreamDecoder::for_profile(&profiles().1);
    truncated.push(&valid[..valid.len() - 1]).unwrap();
    assert_eq!(truncated.finish(), Err(GeminiStreamError::TerminalMissing));
    let mut malformed = GeminiStreamDecoder::new();
    assert_eq!(
        malformed.push(b"data {\n"),
        Err(GeminiStreamError::Malformed)
    );
    let tool = b"data: {\"candidates\":[{\"content\":{\"parts\":[{\"functionCall\":{\"name\":\"x\"}}]},\"index\":0}],\"modelVersion\":\"gemini-native-test\"}\n\n";
    let mut tool_decoder = GeminiStreamDecoder::for_profile(&profiles().1);
    assert_eq!(
        tool_decoder.push(tool),
        Err(GeminiStreamError::UnsupportedContent)
    );
    let anthropic_tool = concat!(
        "event: message_start\n",
        "data: {\"type\":\"message_start\",\"message\":{\"id\":\"tool\",\"type\":\"message\",\"role\":\"assistant\",\"model\":\"claude-native-test\",\"usage\":{\"input_tokens\":1}}}\n\n",
        "event: content_block_start\n",
        "data: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"tool_use\",\"id\":\"x\",\"name\":\"shell\",\"input\":{}}}\n\n"
    );
    let mut anthropic_tool_decoder = AnthropicStreamDecoder::for_profile(&profiles().0);
    assert_eq!(
        anthropic_tool_decoder.push(anthropic_tool.as_bytes()),
        Err(AnthropicStreamError::UnsupportedContent)
    );
    let mut anthropic_terminal = AnthropicStreamDecoder::for_profile(&profiles().0);
    anthropic_terminal
        .push(include_bytes!("../fixtures/anthropic_messages.sse"))
        .unwrap();
    assert_eq!(
        anthropic_terminal.push(b"event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n"),
        Err(AnthropicStreamError::Malformed)
    );
    let duplicate_usage = concat!(
        "data: {\"candidates\":[{\"content\":{\"parts\":[]},\"index\":0}],\"usageMetadata\":{\"promptTokenCount\":1,\"candidatesTokenCount\":1,\"totalTokenCount\":2},\"modelVersion\":\"gemini-native-test\"}\n\n",
        "data: {\"candidates\":[{\"content\":{\"parts\":[]},\"index\":0}],\"usageMetadata\":{\"promptTokenCount\":1,\"candidatesTokenCount\":1,\"totalTokenCount\":2},\"modelVersion\":\"gemini-native-test\"}\n\n"
    );
    let mut usage_decoder = GeminiStreamDecoder::for_profile(&profiles().1);
    usage_decoder.push(duplicate_usage.as_bytes()).unwrap();
    assert_eq!(
        usage_decoder.finish(),
        Err(GeminiStreamError::TerminalMissing)
    );
    let duplicate_terminal = concat!(
        "data: {\"candidates\":[{\"content\":{\"parts\":[]},\"finishReason\":\"STOP\",\"index\":0}],\"usageMetadata\":{\"promptTokenCount\":1,\"candidatesTokenCount\":1,\"totalTokenCount\":2},\"modelVersion\":\"gemini-native-test\"}\n\n",
        "data: {\"candidates\":[{\"content\":{\"parts\":[]},\"finishReason\":\"STOP\",\"index\":0}],\"usageMetadata\":{\"promptTokenCount\":1,\"candidatesTokenCount\":1,\"totalTokenCount\":2},\"modelVersion\":\"gemini-native-test\"}\n\n"
    );
    let mut terminal_decoder = GeminiStreamDecoder::for_profile(&profiles().1);
    assert_eq!(
        terminal_decoder.push(duplicate_terminal.as_bytes()),
        Err(GeminiStreamError::Malformed)
    );
    let huge = format!(
        "data: {{\"candidates\":[{{\"content\":{{\"parts\":[{{\"text\":\"{}\"}}]}},\"index\":0}}],\"modelVersion\":\"gemini-native-test\"}}\n\n",
        "x".repeat(3000)
    );
    let mut oversized = GeminiStreamDecoder::for_profile(&profiles().1);
    assert_eq!(
        oversized.push(huge.as_bytes()),
        Err(GeminiStreamError::BoundExceeded)
    );
}

#[test]
fn anthropic_accepts_ping_thinking_and_sequential_text_blocks_but_rejects_cache_writes() {
    let stream = concat!(
        "event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"id\":\"x\",\"type\":\"message\",\"role\":\"assistant\",\"model\":\"claude-native-test\",\"usage\":{\"input_tokens\":1}}}\n\n",
        "event: ping\ndata: {\"type\":\"ping\"}\n\n",
        "event: content_block_start\ndata: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"thinking\",\"thinking\":\"\"}}\n\n",
        "event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"thinking_delta\",\"thinking\":\"hidden\"}}\n\n",
        "event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"signature_delta\",\"signature\":\"sig\"}}\n\n",
        "event: content_block_stop\ndata: {\"type\":\"content_block_stop\",\"index\":0}\n\n",
        "event: content_block_start\ndata: {\"type\":\"content_block_start\",\"index\":1,\"content_block\":{\"type\":\"text\",\"text\":\"\"}}\n\n",
        "event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":1,\"delta\":{\"type\":\"text_delta\",\"text\":\"ok\"}}\n\n",
        "event: content_block_stop\ndata: {\"type\":\"content_block_stop\",\"index\":1}\n\n",
        "event: message_delta\ndata: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"refusal\"},\"usage\":{\"output_tokens\":2}}\n\n",
        "event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n"
    );
    let events = decode_anthropic(stream.as_bytes()).unwrap();
    assert_eq!(text_output(&events), "ok");
    assert_eq!(
        events
            .iter()
            .filter(|event| matches!(event.kind(), ProviderStreamEventKind::TextDelta { .. }))
            .count(),
        1
    );

    let cache_write = stream.replace(
        "\"input_tokens\":1",
        "\"input_tokens\":1,\"cache_creation_input_tokens\":1",
    );
    assert_eq!(
        decode_anthropic(cache_write.as_bytes()),
        Err(AnthropicStreamError::UnsupportedContent)
    );
}

#[test]
fn gemini_accepts_cumulative_usage_and_explicit_model_alias() {
    let (_, base) = profiles();
    let profile = base
        .with_model_version_alias("gemini-2.5-flash-001")
        .unwrap();
    let mut decoder = GeminiStreamDecoder::for_profile(&profile);
    let stream = concat!(
        "data: {\"candidates\":[{\"content\":{\"parts\":[{\"text\":\"a\",\"thought\":true},{\"text\":\"b\"}]},\"index\":0}],\"modelVersion\":\"gemini-2.5-flash-001\",\"usageMetadata\":{\"promptTokenCount\":1,\"candidatesTokenCount\":0,\"totalTokenCount\":1}}\n\n",
        "data: {\"candidates\":[{\"content\":{\"parts\":[]},\"index\":0}],\"usageMetadata\":{\"promptTokenCount\":2,\"candidatesTokenCount\":1,\"totalTokenCount\":3}}\n\n",
        "data: {\"candidates\":[{\"content\":{\"parts\":[]},\"finishReason\":\"STOP\",\"index\":0}],\"usageMetadata\":{\"promptTokenCount\":2,\"candidatesTokenCount\":1,\"totalTokenCount\":3}}\n\n"
    );
    decoder.push(stream.as_bytes()).unwrap();
    let events = decoder.finish().unwrap();
    assert_eq!(text_output(&events), "b");
    assert_eq!(
        events
            .iter()
            .filter(|event| matches!(event.kind(), ProviderStreamEventKind::Usage { .. }))
            .count(),
        1
    );
}
