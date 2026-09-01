use super::CredentialBrokerFrame;

pub(super) fn valid_frame(frame: &CredentialBrokerFrame) -> bool {
    match frame {
        CredentialBrokerFrame::IssueTicket {
            operation_id,
            attempt,
            command,
            ..
        } => command.operation_id() == *operation_id && command.ticket_attempt() == *attempt,
        CredentialBrokerFrame::Claim {
            operation_id,
            attempt,
            binding,
            secret_offer: Some(offer),
            ..
        } => {
            offer.operation_id == *operation_id
                && offer.attempt == *attempt
                && offer.claim_binding == *binding
        }
        _ => true,
    }
}
