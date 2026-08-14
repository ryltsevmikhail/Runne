// Output formatting utilities

use chrono::{DateTime, Utc};
use gocode_runtime_client::ConversationMessages;

/// Format conversation messages as human-readable text
#[must_use]
#[allow(clippy::format_push_string)]
pub fn format_messages_text(messages: &ConversationMessages) -> String {
    let mut output = String::new();

    for msg in &messages.messages {
        let timestamp = DateTime::<Utc>::from_timestamp_millis(i64::try_from(msg.committed_at).unwrap_or(0))
            .map_or_else(|| "unknown".to_string(), |dt| dt.format("%Y-%m-%d %H:%M:%S").to_string());

        let role = match msg.role {
            gocode_runtime_client::ConversationMessageRole::User => "user",
            gocode_runtime_client::ConversationMessageRole::Assistant => "assistant",
        };

        output.push_str(&format!("[{timestamp}] {role}: {}\n", msg.text));
    }

    output
}

/// Format conversation messages as JSON
#[must_use]
pub fn format_messages_json(messages: &ConversationMessages) -> String {
    serde_json::to_string_pretty(messages).unwrap_or_else(|_| "{}".to_string())
}
