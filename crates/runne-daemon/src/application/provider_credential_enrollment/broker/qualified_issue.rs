use super::{ProviderCredentialBroker, map_store, qualified_exchange::QualifiedIssuedTicket};
use runne_api::ProviderCredentialEnrollmentHostError as Error;
use runne_provider::{
    AttachCredentialProcess, IssueCredentialTicketDigest, MeasuredQualificationAdmission,
    ProviderCredentialEnrollmentStore, ProviderQualificationAdmissionFenceReceipt,
    RawCredentialTicket,
};

impl ProviderCredentialBroker {
    /// Commits a qualified attempt without delivering broker or service bytes.
    pub(crate) fn issue_qualified_ticket<S: ProviderCredentialEnrollmentStore>(
        &self,
        admission: MeasuredQualificationAdmission,
        store: &S,
    ) -> Result<
        (
            QualifiedIssuedTicket,
            ProviderQualificationAdmissionFenceReceipt,
        ),
        Error,
    > {
        let operation = admission.metadata().operation_id();
        let continuation = admission.continuation_binding_digest();
        let ticket = RawCredentialTicket::generate().map_err(|_| Error::Unavailable)?;
        store
            .attach_process(
                AttachCredentialProcess::new(operation, continuation)
                    .map_err(|_| Error::AccessDenied)?,
            )
            .map_err(map_store)?;
        let issued = store
            .issue_ticket_attempt_with_qualification_fence(
                IssueCredentialTicketDigest::new(
                    operation,
                    ticket.binding_digest(),
                    continuation,
                    60,
                )
                .map_err(|_| Error::AccessDenied)?,
                admission,
            )
            .map_err(map_store)?;
        self.validate_qualification_receipt(&issued.1)?;
        Ok((QualifiedIssuedTicket::new(ticket, issued.0), issued.1))
    }

    pub(crate) fn validate_qualification_receipt(
        &self,
        receipt: &ProviderQualificationAdmissionFenceReceipt,
    ) -> Result<(), Error> {
        self.measurements
            .validate_qualification_receipt(receipt)
            .map_err(|_| Error::AccessDenied)
    }
}
