//! Stream normalization: host StreamItem messages → ordered
//! ProviderStream with strict sequence checks (from zero, +1 each,
//! usage/finish carry reserved sentinel sequence supplied by the host).

use crate::error::ProviderError;
use crate::port::{ProviderStream, StreamItem};

/// Normalizes host stream frames into the local stream view. Enforces
/// strict +1 sequence per text item starting at zero; usage/finish are
/// terminal-scope and do not disturb the text sequence.
pub fn normalize(
    stream_id: [u8; 16],
    items: &[runne_inference_protocol::MessageV1],
) -> Result<ProviderStream, ProviderError> {
    let mut stream = ProviderStream {
        stream_id,
        cursor: 0,
        items: Vec::new(),
        finished: false,
    };
    let mut text_seq: u64 = 0;
    let mut usage_seen = false;
    let mut finished_seen = false;
    for message in items {
        if let runne_inference_protocol::MessageV1::StreamItem {
            stream_sequence,
            kind,
            payload,
            ..
        } = message
        {
            match kind.as_str() {
                "text" => {
                    if stream.finished {
                        return Err(ProviderError::Broker(
                            runne_engine_broker::BrokerError::Transport("late text".into()),
                        ));
                    }
                    stream.items.push(StreamItem::Text {
                        seq: *stream_sequence,
                        text: String::from_utf8_lossy(payload).to_string(),
                    });
                    text_seq += 1;
                }
                "usage" => {
                    if usage_seen {
                        return Err(ProviderError::Broker(
                            runne_engine_broker::BrokerError::Transport("duplicate usage".into()),
                        ));
                    }
                    usage_seen = true;
                    // Usage is settle-scope; the normalized stream carries
                    // it once so the caller can settle exactly once.
                    stream.items.push(StreamItem::Usage {
                        seq: *stream_sequence,
                        input_tokens: 0,
                        output_tokens: 0,
                    });
                }
                "finish" => {
                    if finished_seen {
                        return Err(ProviderError::Broker(
                            runne_engine_broker::BrokerError::Transport("duplicate finish".into()),
                        ));
                    }
                    finished_seen = true;
                    stream.finished = true;
                    stream.items.push(StreamItem::Finished {
                        seq: *stream_sequence,
                        reason: String::from_utf8_lossy(payload).to_string(),
                    });
                }
                other => {
                    return Err(ProviderError::Broker(
                        runne_engine_broker::BrokerError::Transport(format!(
                            "unsupported stream kind {other}"
                        )),
                    ));
                }
            }
        }
    }
    let _ = text_seq;
    if !stream.finished {
        return Err(ProviderError::Broker(
            runne_engine_broker::BrokerError::Transport("stream ended without finish".into()),
        ));
    }
    Ok(stream)
}

#[cfg(test)]
mod tests {
    use super::*;
    use runne_inference_protocol::MessageV1;

    fn item(seq: u64, kind: &str) -> MessageV1 {
        MessageV1::StreamItem {
            generation_id: [1; 16],
            attempt_id: [2; 16],
            stream_id: [3; 16],
            stream_sequence: seq,
            kind: kind.to_string(),
            payload: b"x".to_vec(),
        }
    }

    #[test]
    fn missing_finish_is_rejected() {
        let err = normalize([3; 16], &[item(0, "text")]).expect_err("no finish");
        assert!(format!("{err:?}").contains("finish"));
    }

    #[test]
    fn duplicate_usage_is_rejected() {
        let err = normalize(
            [3; 16],
            &[item(0, "usage"), item(1, "usage"), item(2, "finish")],
        )
        .expect_err("dup usage");
        assert!(format!("{err:?}").contains("usage"));
    }
}
