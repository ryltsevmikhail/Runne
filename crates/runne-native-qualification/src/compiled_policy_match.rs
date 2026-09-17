/// Compares protected policy pins with the existing compiled authorities.
///
/// This read-only check neither installs keys nor creates admission authority.
/// Missing, malformed, or non-distinct compiled authorities always reject.
#[must_use]
pub fn qualification_bootstrap_compiled_authorities_match(
    context_public_key: [u8; 32],
    context_key_id: [u8; 32],
    fault_public_key: [u8; 32],
    fault_key_id: [u8; 32],
) -> bool {
    matches(
        crate::context_policy::load(),
        crate::compiled_policy::load(),
        context_public_key,
        context_key_id,
        fault_public_key,
        fault_key_id,
    )
}

pub fn matches(
    context: Option<crate::context_policy::ContextVerificationPolicy>,
    fault: Option<crate::compiled_policy::FaultVerificationPolicy>,
    context_public_key: [u8; 32],
    context_key_id: [u8; 32],
    fault_public_key: [u8; 32],
    fault_key_id: [u8; 32],
) -> bool {
    let (Some(context), Some(fault)) = (context, fault) else {
        return false;
    };
    crate::context_policy::authorities_are_distinct(&context, &fault)
        && context.key.to_bytes() == context_public_key
        && context.key_id == context_key_id
        && fault.key.to_bytes() == fault_public_key
        && fault.key_id == fault_key_id
}
