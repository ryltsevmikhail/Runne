use crate::profile::ChatCompletionsAccounting;

const fn same(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    if a.len() != b.len() {
        return false;
    }
    let mut i = 0;
    while i < a.len() {
        if a[i] != b[i] {
            return false;
        }
        i += 1;
    }
    true
}

pub(super) const fn for_provider(provider: &str) -> ChatCompletionsAccounting {
    if same(provider, "zai")
        || same(provider, "zai-coding-cn")
        || same(provider, "qwen-token-plan")
        || same(provider, "qwen-token-plan-cn")
        || same(provider, "qwen-token-plan-individual")
        || same(provider, "xiaomi-token-plan-ams")
        || same(provider, "xiaomi-token-plan-cn")
        || same(provider, "xiaomi-token-plan-sgp")
    {
        return ChatCompletionsAccounting::SubscriptionQuotaExternallyMetered;
    }
    if same(provider, "nvidia") {
        return ChatCompletionsAccounting::ExternallyBilledUnpriced;
    }
    if same(provider, "xiaomi") {
        return ChatCompletionsAccounting::Payg {
            input_micros_per_million: 140_000,
            output_micros_per_million: 280_000,
            cached_input_micros_per_million: 2_800,
        };
    }
    let (input, output, cached) = if same(provider, "ant-ling") {
        (60, 250, 0)
    } else if same(provider, "baseten") {
        (130, 260, 28)
    } else if same(provider, "cerebras") {
        (990, 1490, 0)
    } else if same(provider, "groq") {
        (50, 80, 0)
    } else if same(provider, "huggingface") {
        (300, 1200, 0)
    } else if same(provider, "moonshotai") || same(provider, "moonshotai-cn") {
        (600, 2500, 150)
    } else if same(provider, "together") {
        (300, 1200, 60)
    } else if same(provider, "openrouter") {
        (800, 1600, 200)
    } else if same(provider, "opencode") || same(provider, "fireworks") {
        (150, 500, 30)
    } else if same(provider, "mistral") {
        (100, 300, 10)
    } else if same(provider, "opencode-go") {
        return ChatCompletionsAccounting::SubscriptionQuotaExternallyMetered;
    } else {
        return ChatCompletionsAccounting::ExternallyBilledUnpriced;
    };
    ChatCompletionsAccounting::Payg {
        input_micros_per_million: input * 1_000,
        output_micros_per_million: output * 1_000,
        cached_input_micros_per_million: cached * 1_000,
    }
}
