use super::protocol::{ErrorV1, ReceiptV1};
use base64::{Engine, engine::general_purpose::STANDARD};
use serde::Deserialize;
use sha2::{Digest, Sha256};

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum OutputV1 {
    Receipt(Box<ReceiptV1>),
    Error(ErrorV1),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum OutputError {
    Invalid,
    Denied,
    Uncertain,
}

pub(crate) fn parse_output(bytes: &[u8]) -> Result<ReceiptV1, OutputError> {
    if bytes.is_empty() || bytes.len() > 16 * 1024 {
        return Err(OutputError::Invalid);
    }
    match serde_json::from_slice(bytes).map_err(|_| OutputError::Invalid)? {
        OutputV1::Receipt(receipt)
            if receipt.status == "success"
                && receipt.version == 1
                && !receipt.truncated
                && receipt.byte_length <= 8 * 1024 =>
        {
            let content = STANDARD
                .decode(receipt.bytes_base64.as_bytes())
                .map_err(|_| OutputError::Invalid)?;
            if content.len() != receipt.byte_length
                || hex::encode(Sha256::digest(&content)) != receipt.sha256
            {
                return Err(OutputError::Invalid);
            }
            Ok(*receipt)
        }
        OutputV1::Error(error) if error.status == "error" && error.version == 1 => {
            Err(if error.effect_started {
                OutputError::Uncertain
            } else {
                OutputError::Denied
            })
        }
        _ => Err(OutputError::Invalid),
    }
}
