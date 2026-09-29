//! Durable conversation writer lease (X2 writer lease v1).
//!
//! One conversation has at most one mutation writer at a time. The FIRST
//! mutating principal acquires the lease (fencing token 1); every later
//! mutation by the same principal renews it; a mutation by any other
//! principal is denied until an authenticated take-control with the exact
//! expected fencing token rotates the lease. The lease never expires on its
//! own — expiry does not prove the old writer died (plan 18 §D1.3/X2), only
//! take-control changes ownership.

use rusqlite::{Connection, OptionalExtension, Transaction, TransactionBehavior};

/// Snapshot of one durable writer lease.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConversationWriterLease {
    pub owner_principal: String,
    pub fencing_token: u64,
}

/// Outcome of a writer-lease check for one mutating principal.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum WriterLeaseDecision {
    /// No lease existed: this principal acquired it with the given token.
    Acquired(u64),
    /// The principal already owned the lease; token unchanged.
    Held(u64),
}

/// Closed writer-lease failures.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WriterLeaseError {
    /// Another principal holds the lease; mutation denied.
    FencedByOtherWriter,
    /// The expected fencing token did not match; take-control denied.
    Conflict,
    /// Durable store failure.
    Unavailable,
}

/// Ensures `principal` may mutate `conversation_id`, acquiring or renewing
/// the lease inside the caller's transaction.
///
/// # Errors
///
/// [`WriterLeaseError::FencedByOtherWriter`] when a different principal owns
/// the lease; [`WriterLeaseError::Unavailable`] on store failure.
pub fn ensure_writer_lease(
    transaction: &Transaction<'_>,
    conversation_id: &[u8; 16],
    principal: &str,
    now_unix: i64,
) -> Result<WriterLeaseDecision, WriterLeaseError> {
    let existing: Option<(String, i64)> = transaction
        .query_row(
            "SELECT owner_principal, fencing_token FROM conversation_writer_leases
             WHERE conversation_id = ?1",
            [conversation_id.as_slice()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()
        .map_err(|_| WriterLeaseError::Unavailable)?;
    match existing {
        None => {
            transaction
                .execute(
                    "INSERT INTO conversation_writer_leases
                     (conversation_id, owner_principal, fencing_token, taken_at_unix)
                     VALUES (?1, ?2, 1, ?3)",
                    rusqlite::params![conversation_id.as_slice(), principal, now_unix],
                )
                .map_err(|_| WriterLeaseError::Unavailable)?;
            Ok(WriterLeaseDecision::Acquired(1))
        }
        Some((owner, token)) if owner == principal => Ok(WriterLeaseDecision::Held(token as u64)),
        Some(_) => Err(WriterLeaseError::FencedByOtherWriter),
    }
}

/// Rotates the lease to `new_principal` after matching `expected_token`.
/// Returns the new fencing token.
///
/// # Errors
///
/// [`WriterLeaseError::Conflict`] on token mismatch (including a missing
/// lease); [`WriterLeaseError::Unavailable`] on store failure.
pub fn take_control_writer_lease(
    transaction: &Transaction<'_>,
    conversation_id: &[u8; 16],
    expected_token: u64,
    new_principal: &str,
    now_unix: i64,
) -> Result<u64, WriterLeaseError> {
    let updated = transaction
        .execute(
            "UPDATE conversation_writer_leases
             SET owner_principal = ?2, fencing_token = fencing_token + 1, taken_at_unix = ?3
             WHERE conversation_id = ?1 AND fencing_token = ?4",
            rusqlite::params![
                conversation_id.as_slice(),
                new_principal,
                now_unix,
                expected_token as i64
            ],
        )
        .map_err(|_| WriterLeaseError::Unavailable)?;
    if updated != 1 {
        return Err(WriterLeaseError::Conflict);
    }
    let token: i64 = transaction
        .query_row(
            "SELECT fencing_token FROM conversation_writer_leases WHERE conversation_id = ?1",
            [conversation_id.as_slice()],
            |row| row.get(0),
        )
        .map_err(|_| WriterLeaseError::Unavailable)?;
    Ok(token as u64)
}

/// Reads the durable lease for a conversation, if any.
///
/// # Errors
///
/// [`WriterLeaseError::Unavailable`] on store failure.
pub fn load_writer_lease(
    connection: &Connection,
    conversation_id: &[u8; 16],
) -> Result<Option<ConversationWriterLease>, WriterLeaseError> {
    connection
        .query_row(
            "SELECT owner_principal, fencing_token FROM conversation_writer_leases
             WHERE conversation_id = ?1",
            [conversation_id.as_slice()],
            |row| {
                Ok(ConversationWriterLease {
                    owner_principal: row.get(0)?,
                    fencing_token: row.get::<_, i64>(1)? as u64,
                })
            },
        )
        .optional()
        .map_err(|_| WriterLeaseError::Unavailable)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::Connection;

    fn leased_db() -> Connection {
        let connection = Connection::open_in_memory().expect("memory db");
        crate::schema::apply_migrations(&connection).expect("migrations");
        connection
    }

    fn tx(connection: &Connection) -> Transaction<'_> {
        Transaction::new_unchecked(connection, TransactionBehavior::Immediate).expect("tx")
    }

    const CONVERSATION: [u8; 16] = [7; 16];

    #[test]
    fn first_mutator_acquires_and_same_principal_holds() {
        let connection = leased_db();
        let transaction = tx(&connection);
        assert_eq!(
            ensure_writer_lease(&transaction, &CONVERSATION, "alice", 100),
            Ok(WriterLeaseDecision::Acquired(1))
        );
        assert_eq!(
            ensure_writer_lease(&transaction, &CONVERSATION, "alice", 200),
            Ok(WriterLeaseDecision::Held(1))
        );
        transaction.commit().expect("commit");
        assert_eq!(
            load_writer_lease(&connection, &CONVERSATION),
            Ok(Some(ConversationWriterLease {
                owner_principal: "alice".to_owned(),
                fencing_token: 1,
            }))
        );
    }

    #[test]
    fn other_principal_is_fenced_until_take_control() {
        let connection = leased_db();
        let transaction = tx(&connection);
        ensure_writer_lease(&transaction, &CONVERSATION, "alice", 100).expect("alice acquires");
        assert_eq!(
            ensure_writer_lease(&transaction, &CONVERSATION, "bob", 300),
            Err(WriterLeaseError::FencedByOtherWriter)
        );
        let new_token =
            take_control_writer_lease(&transaction, &CONVERSATION, 1, "bob", 300).expect("take");
        assert_eq!(new_token, 2);
        assert_eq!(
            ensure_writer_lease(&transaction, &CONVERSATION, "bob", 300),
            Ok(WriterLeaseDecision::Held(2))
        );
        assert_eq!(
            ensure_writer_lease(&transaction, &CONVERSATION, "alice", 400),
            Err(WriterLeaseError::FencedByOtherWriter)
        );
        transaction.commit().expect("commit");
    }

    #[test]
    fn take_control_with_a_stale_token_conflicts() {
        let connection = leased_db();
        let transaction = tx(&connection);
        ensure_writer_lease(&transaction, &CONVERSATION, "alice", 100).expect("alice acquires");
        assert_eq!(
            take_control_writer_lease(&transaction, &CONVERSATION, 9, "bob", 300),
            Err(WriterLeaseError::Conflict)
        );
        assert_eq!(
            take_control_writer_lease(&transaction, &[8; 16], 1, "bob", 300),
            Err(WriterLeaseError::Conflict)
        );
        transaction.commit().expect("commit");
    }
}
