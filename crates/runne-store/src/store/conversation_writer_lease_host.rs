use rusqlite::Transaction;

use crate::conversation_writer_lease::{WriterLeaseError, take_control_writer_lease, unix_now};

use super::StoreTransaction;

impl StoreTransaction {
    /// Rotates the conversation writer lease to `new_principal` after the
    /// exact `expected_token` matches, in one durable store transaction.
    ///
    /// # Errors
    ///
    /// Propagates [`WriterLeaseError::Conflict`] on token mismatch and
    /// [`WriterLeaseError::Unavailable`] on store failure.
    pub fn take_control_conversation_writer_lease(
        &self,
        conversation_id: &[u8; 16],
        new_principal: &str,
        expected_token: u64,
    ) -> Result<u64, WriterLeaseError> {
        use rusqlite::TransactionBehavior;

        let connection = self
            .inner
            .writer
            .lock()
            .map_err(|_| WriterLeaseError::Unavailable)?;
        let transaction = Transaction::new_unchecked(&connection, TransactionBehavior::Immediate)
            .map_err(|_| WriterLeaseError::Unavailable)?;
        let token = take_control_writer_lease(
            &transaction,
            conversation_id,
            expected_token,
            new_principal,
            unix_now(),
        )?;
        transaction
            .commit()
            .map_err(|_| WriterLeaseError::Unavailable)?;
        Ok(token)
    }
}
