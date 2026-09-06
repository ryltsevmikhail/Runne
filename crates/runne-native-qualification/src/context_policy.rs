use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::VerifyingKey;
use sha2::{Digest as _, Sha256};

pub struct ContextVerificationPolicy {
    pub key: VerifyingKey,
    pub key_id: [u8; 32],
}

pub fn load() -> Option<ContextVerificationPolicy> {
    let context = decode_policy(
        option_env!("RUNNE_DPK_CONTEXT_PUBLIC_KEY_B64URL"),
        option_env!("RUNNE_DPK_CONTEXT_KEY_ID"),
    );
    select_distinct_policy(context, crate::compiled_policy::load())
}

pub fn select_distinct_policy(
    context: Option<ContextVerificationPolicy>,
    fault: Option<crate::compiled_policy::FaultVerificationPolicy>,
) -> Option<ContextVerificationPolicy> {
    let context = context?;
    let fault = fault?;
    authorities_are_distinct(&context, &fault).then_some(context)
}

pub fn authorities_are_distinct(
    context: &ContextVerificationPolicy,
    fault: &crate::compiled_policy::FaultVerificationPolicy,
) -> bool {
    context.key.as_bytes() != fault.key.as_bytes() && context.key_id != fault.key_id
}

pub fn decode_policy(
    encoded_key: Option<&str>,
    encoded_key_id: Option<&str>,
) -> Option<ContextVerificationPolicy> {
    let encoded_key = encoded_key?;
    let key_bytes: [u8; 32] = URL_SAFE_NO_PAD.decode(encoded_key).ok()?.try_into().ok()?;
    if URL_SAFE_NO_PAD.encode(key_bytes) != encoded_key {
        return None;
    }
    let key = VerifyingKey::from_bytes(&key_bytes).ok()?;
    let encoded_key_id = encoded_key_id?;
    let key_id: [u8; 32] = hex::decode(encoded_key_id).ok()?.try_into().ok()?;
    if hex::encode(key_id) != encoded_key_id || Sha256::digest(key_bytes).as_slice() != key_id {
        return None;
    }
    Some(ContextVerificationPolicy { key, key_id })
}
