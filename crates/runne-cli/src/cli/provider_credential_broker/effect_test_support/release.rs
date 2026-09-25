use runne_provider::{
    CredentialBindingDigest, CredentialBrokerCommand, CredentialBrokerFrame,
    CredentialBrokerFrameCodec, CredentialOperationAction,
};

pub(super) fn append_non_pair(input: &mut Vec<u8>, command: &CredentialBrokerCommand) {
    if command.action() == CredentialOperationAction::Pair {
        return;
    }
    CredentialBrokerFrameCodec::write_to(
        input,
        CredentialBrokerFrame::NativeEffectRelease {
            operation_id: command.operation_id(),
            attempt: command.ticket_attempt(),
            binding: CredentialBindingDigest::from_measured([13; 32]).expect("binding"),
        },
    )
    .expect("non-Pair release");
}
