pub(super) fn relay_ack_allowed(
    relay_taken: bool,
    terminal: bool,
    retained: Option<&[u8; runne_api::PROTECTED_CREDENTIAL_SECRET_RELAY_BYTES]>,
    provided: &[u8; runne_api::PROTECTED_CREDENTIAL_SECRET_RELAY_BYTES],
) -> bool {
    relay_taken && !terminal && retained == Some(provided)
}
