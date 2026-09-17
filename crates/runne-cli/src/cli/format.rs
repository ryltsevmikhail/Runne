// Output formatting utilities

use chrono::{DateTime, Utc};
use runne_runtime_client::ConversationMessages;

/// Format conversation messages as human-readable text
#[must_use]
#[allow(clippy::format_push_string)]
pub fn format_messages_text(messages: &ConversationMessages) -> String {
    let mut output = String::new();

    for msg in &messages.messages {
        let timestamp = DateTime::<Utc>::from_timestamp_millis(i64::try_from(msg.committed_at).unwrap_or(0))
            .map_or_else(|| "unknown".to_string(), |dt| dt.format("%Y-%m-%d %H:%M:%S").to_string());

        let role = match msg.role {
            runne_runtime_client::ConversationMessageRole::User => "user",
            runne_runtime_client::ConversationMessageRole::Assistant => "assistant",
        };

        output.push_str(&format!("[{timestamp}] {role}: {}\n", msg.text));
    }

    output
}

/// Typed JSON `data` payload for conversation messages; serialized once at
/// render time, never pre-serialized into a string payload.
#[must_use]
pub fn messages_json_data(messages: &ConversationMessages) -> serde_json::Value {
    serde_json::to_value(messages).unwrap_or(serde_json::Value::Null)
}
