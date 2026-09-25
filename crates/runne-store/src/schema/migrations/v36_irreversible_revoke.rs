pub(super) const MIGRATION_CREDENTIAL_V36: &str = r#"
CREATE TRIGGER provider_credential_revoke_irreversible
BEFORE UPDATE ON provider_credential_operations
WHEN OLD.action = 'REVOKE'
 AND OLD.state = 'PREPARED'
 AND NEW.state IN ('FAILED', 'EXPIRED', 'CANCELLED')
BEGIN
    SELECT RAISE(ABORT, 'fenced revoke cannot close before reconciliation');
END;
"#;
