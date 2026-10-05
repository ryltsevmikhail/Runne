use runne_secure_store::{SecureStore, SecurityProfileLock};
use rusqlite::{TransactionBehavior, params};
use zeroize::Zeroizing;

use crate::{LocalStore, SecurityContext};

use super::crypto::{current_draft, scope_token, seal, validate_scope, validate_scope_token};
use super::schema::{ensure_schema, map_write_error, open_database};
use super::types::{
    MAX_DRAFT_BYTES, MAX_DRAFT_REVISION, MAX_DRAFT_SLOTS, ProtectedDraft, ProtectedDraftError,
    ProtectedDraftScope,
};

impl LocalStore {
    /// Loads one authenticated draft or its durable tombstone.
    ///
    /// # Errors
    /// Returns an error when the secure store, sidecar, scope, or ciphertext is unavailable.
    pub fn load_protected_draft(
        &self,
        secure: &dyn SecureStore,
        scope: &ProtectedDraftScope,
    ) -> Result<ProtectedDraft, ProtectedDraftError> {
        validate_scope(scope)?;
        let context = self.context()?;
        self.validate_protected_draft_owner(context)?;
        let lock = draft_lock(secure, context)?;
        let token = scope_token(context.profile, context.database, scope);
        let mut connection = open_database(&context.path)?;
        ensure_schema(&mut connection)?;
        let transaction = connection
            .transaction()
            .map_err(|_| ProtectedDraftError::Storage)?;
        let draft = current_draft(
            &transaction,
            &lock,
            context.profile,
            context.database,
            scope,
            &token,
        )?;
        transaction
            .commit()
            .map_err(|_| ProtectedDraftError::Storage)?;
        Ok(draft)
    }

    /// Saves a draft only when both its opaque scope token and revision match.
    ///
    /// # Errors
    /// Returns an error when the scope, expected revision, protected store, or capacity is invalid.
    pub fn save_protected_draft(
        &self,
        secure: &dyn SecureStore,
        scope: &ProtectedDraftScope,
        expected_scope_token: &str,
        expected_revision: u64,
        prompt: &str,
    ) -> Result<ProtectedDraft, ProtectedDraftError> {
        validate_scope(scope)?;
        validate_scope_token(expected_scope_token)?;
        validate_prompt(prompt)?;
        let context = self.context()?;
        let token = scope_token(context.profile, context.database, scope);
        if token != expected_scope_token {
            return Err(ProtectedDraftError::ScopeMismatch);
        }
        validate_revision(expected_revision)?;
        self.validate_protected_draft_owner(context)?;
        let lock = draft_lock(secure, context)?;
        let mut connection = open_database(&context.path)?;
        ensure_schema(&mut connection)?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| ProtectedDraftError::Storage)?;
        let prior = current_draft(
            &transaction,
            &lock,
            context.profile,
            context.database,
            scope,
            &token,
        )?
        .revision;
        if prior != expected_revision {
            return Err(ProtectedDraftError::Conflict);
        }
        let revision = next_revision(prior)?;
        let plaintext = Zeroizing::new(prompt.as_bytes().to_vec());
        let envelope = seal(
            &lock,
            context.profile,
            context.database,
            scope,
            revision,
            &plaintext,
        )?;
        if prior == 0 {
            let count: i64 = transaction
                .query_row("SELECT COUNT(*) FROM protected_drafts", [], |row| {
                    row.get(0)
                })
                .map_err(|_| ProtectedDraftError::Storage)?;
            if count >= MAX_DRAFT_SLOTS {
                return Err(ProtectedDraftError::Capacity);
            }
            transaction.execute(
                "INSERT INTO protected_drafts(lineage,authority,principal,project_id,workspace_id,revision,deleted,payload) VALUES(?1,?2,?3,?4,?5,?6,0,?7)",
                params![scope.lineage, scope.authority, scope.principal, scope.project_id, scope.workspace_id, revision, envelope],
            ).map_err(|error| map_write_error(&error))?;
        } else {
            let changed = transaction.execute(
                "UPDATE protected_drafts SET revision=?6, deleted=0, payload=?7 WHERE lineage=?1 AND authority=?2 AND principal=?3 AND project_id=?4 AND workspace_id=?5 AND revision=?8",
                params![scope.lineage, scope.authority, scope.principal, scope.project_id, scope.workspace_id, revision, envelope, prior],
            ).map_err(|_| ProtectedDraftError::Storage)?;
            if changed != 1 {
                return Err(ProtectedDraftError::Conflict);
            }
        }
        transaction
            .commit()
            .map_err(|_| ProtectedDraftError::Storage)?;
        Ok(ProtectedDraft {
            revision,
            prompt: Some(prompt.to_owned()),
            scope_token: token,
        })
    }

    /// Clears a draft with compare-and-swap and accepts a retry after its tombstone commits.
    ///
    /// # Errors
    /// Returns an error when the scope, expected revision, or protected store is unavailable.
    pub fn clear_protected_draft(
        &self,
        secure: &dyn SecureStore,
        scope: &ProtectedDraftScope,
        expected_scope_token: &str,
        expected_revision: u64,
    ) -> Result<ProtectedDraft, ProtectedDraftError> {
        validate_scope(scope)?;
        validate_scope_token(expected_scope_token)?;
        let context = self.context()?;
        let token = scope_token(context.profile, context.database, scope);
        if token != expected_scope_token {
            return Err(ProtectedDraftError::ScopeMismatch);
        }
        validate_revision(expected_revision)?;
        self.validate_protected_draft_owner(context)?;
        let lock = draft_lock(secure, context)?;
        let mut connection = open_database(&context.path)?;
        ensure_schema(&mut connection)?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| ProtectedDraftError::Storage)?;
        let current = current_draft(
            &transaction,
            &lock,
            context.profile,
            context.database,
            scope,
            &token,
        )?;
        if current.revision != expected_revision {
            let already_cleared = current.prompt.is_none()
                && expected_revision.checked_add(1) == Some(current.revision);
            if already_cleared {
                transaction
                    .commit()
                    .map_err(|_| ProtectedDraftError::Storage)?;
                return Ok(current);
            }
            return Err(ProtectedDraftError::Conflict);
        }
        if current.revision == 0 {
            transaction
                .commit()
                .map_err(|_| ProtectedDraftError::Storage)?;
            return Ok(current);
        }
        if current.prompt.is_none() {
            return Err(ProtectedDraftError::Conflict);
        }
        let revision = next_revision(current.revision)?;
        let envelope = seal(
            &lock,
            context.profile,
            context.database,
            scope,
            revision,
            &[],
        )?;
        let changed = transaction.execute(
            "UPDATE protected_drafts SET revision=?6, deleted=1, payload=?7 WHERE lineage=?1 AND authority=?2 AND principal=?3 AND project_id=?4 AND workspace_id=?5 AND revision=?8",
            params![scope.lineage, scope.authority, scope.principal, scope.project_id, scope.workspace_id, revision, envelope, current.revision],
        ).map_err(|_| ProtectedDraftError::Storage)?;
        if changed != 1 {
            return Err(ProtectedDraftError::Conflict);
        }
        transaction
            .commit()
            .map_err(|_| ProtectedDraftError::Storage)?;
        Ok(ProtectedDraft {
            revision,
            prompt: None,
            scope_token: token,
        })
    }

    fn context(&self) -> Result<&SecurityContext, ProtectedDraftError> {
        self.security
            .as_ref()
            .ok_or(ProtectedDraftError::Unavailable)
    }

    fn validate_protected_draft_owner(
        &self,
        context: &SecurityContext,
    ) -> Result<(), ProtectedDraftError> {
        if context.poisoned
            || runne_sqlite_native_identity::opened_database_identity(&self.connection).ok()
                != Some(context.file_identity)
            || runne_sqlite_native_identity::path_database_identity(&context.path).ok()
                != Some(context.file_identity)
        {
            return Err(ProtectedDraftError::Unavailable);
        }
        Ok(())
    }
}

fn draft_lock<'a>(
    secure: &'a dyn SecureStore,
    context: &SecurityContext,
) -> Result<SecurityProfileLock<'a>, ProtectedDraftError> {
    let lock = secure
        .acquire_security_profile_lock(context.profile)
        .map_err(|_| ProtectedDraftError::Unavailable)?;
    if !lock.supports_mutation_payload_encryption() {
        return Err(ProtectedDraftError::Unavailable);
    }
    Ok(lock)
}

const fn validate_prompt(prompt: &str) -> Result<(), ProtectedDraftError> {
    if prompt.is_empty() || prompt.len() > MAX_DRAFT_BYTES {
        return Err(ProtectedDraftError::Invalid);
    }
    Ok(())
}

const fn validate_revision(revision: u64) -> Result<(), ProtectedDraftError> {
    if revision > MAX_DRAFT_REVISION {
        return Err(ProtectedDraftError::Invalid);
    }
    Ok(())
}

fn next_revision(revision: u64) -> Result<u64, ProtectedDraftError> {
    revision
        .checked_add(1)
        .filter(|next| *next <= MAX_DRAFT_REVISION)
        .ok_or(ProtectedDraftError::Capacity)
}
