use serde::Deserialize;
use serde_json::Value;

#[derive(Deserialize)]
pub struct Chunk {
    #[serde(default)]
    pub(super) id: Option<String>,
    #[serde(default)]
    pub(super) model: Option<String>,
    #[serde(default)]
    pub(super) choices: Vec<Choice>,
    pub(super) usage: Option<Usage>,
}
#[derive(Deserialize)]
pub struct Choice {
    pub(super) delta: Delta,
    pub(super) finish_reason: Option<String>,
}
#[derive(Deserialize, Default)]
pub struct Delta {
    pub(super) content: Option<String>,
    #[serde(default)]
    pub(super) tool_calls: Option<Value>,
}
#[derive(Deserialize)]
pub struct Usage {
    pub(super) prompt_tokens: u64,
    pub(super) completion_tokens: u64,
    #[serde(default)]
    pub(super) total_tokens: Option<u64>,
    #[serde(default)]
    pub(super) prompt_tokens_details: Option<UsageDetails>,
    #[serde(default)]
    pub(super) completion_tokens_details: Option<CompletionUsageDetails>,
}
#[derive(Deserialize)]
pub struct UsageDetails {
    #[serde(default)]
    pub(super) cached_tokens: u64,
}
#[derive(Deserialize, Default)]
pub struct CompletionUsageDetails {
    #[serde(default)]
    pub(super) reasoning_tokens: u64,
}
