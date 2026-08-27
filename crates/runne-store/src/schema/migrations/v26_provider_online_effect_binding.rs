pub(super) const MIGRATION_V26: &str = r#"
CREATE TABLE provider_online_dispatch_issuance_evidence (
    dispatch_attempt_id BLOB NOT NULL PRIMARY KEY
        REFERENCES provider_execution_admissions(dispatch_attempt_id),
    provider_id TEXT NOT NULL CHECK(length(CAST(provider_id AS BLOB)) BETWEEN 1 AND 128),
    authority_id BLOB NOT NULL CHECK(length(authority_id) = 16),
    authority_revision INTEGER NOT NULL CHECK(authority_revision > 0),
    issued_at INTEGER NOT NULL CHECK(issued_at >= 0),
    proof_version INTEGER NOT NULL CHECK(proof_version = 1),
    journal_key_id BLOB NOT NULL CHECK(length(journal_key_id) = 16),
    journal_key_version INTEGER NOT NULL CHECK(journal_key_version > 0),
    journal_runtime_authority_id BLOB NOT NULL CHECK(length(journal_runtime_authority_id) = 16),
    journal_database_generation INTEGER NOT NULL CHECK(journal_database_generation > 0),
    issuance_mac BLOB NOT NULL CHECK(length(issuance_mac) = 32)
);
CREATE TABLE provider_online_dispatch_claim_providers (
    dispatch_attempt_id BLOB NOT NULL PRIMARY KEY
        REFERENCES provider_execution_admissions(dispatch_attempt_id),
    provider_id TEXT NOT NULL CHECK(length(CAST(provider_id AS BLOB)) BETWEEN 1 AND 128)
);
CREATE TABLE provider_online_credential_effect_bindings (
    dispatch_attempt_id BLOB NOT NULL PRIMARY KEY
        REFERENCES provider_effect_starts(dispatch_attempt_id),
    provider_id TEXT NOT NULL REFERENCES provider_credential_authority_heads(provider_id),
    launch_generation INTEGER NOT NULL CHECK(launch_generation > 0),
    lifecycle_revision INTEGER NOT NULL CHECK(lifecycle_revision > 0),
    credential_fence INTEGER NOT NULL CHECK(credential_fence > 0),
    active_credential_version INTEGER NOT NULL CHECK(active_credential_version > 0),
    active_ref_digest BLOB NOT NULL CHECK(length(active_ref_digest) = 32),
    effect_mac BLOB NOT NULL CHECK(length(effect_mac) = 32),
    FOREIGN KEY(provider_id, active_credential_version)
        REFERENCES provider_credential_versions(provider_id, credential_version)
);
CREATE TRIGGER provider_online_dispatch_issuance_evidence_insert_current
BEFORE INSERT ON provider_online_dispatch_issuance_evidence
WHEN NOT EXISTS(
    SELECT 1 FROM provider_execution_admissions admission
    JOIN provider_effect_authorities authority
      ON authority.authority_id = admission.authority_id
     AND authority.revision = admission.authority_revision
    WHERE admission.dispatch_attempt_id = NEW.dispatch_attempt_id
      AND admission.authority_id = NEW.authority_id
      AND admission.authority_revision = NEW.authority_revision
      AND admission.issued_at = NEW.issued_at
      AND authority.attempt_id = NEW.dispatch_attempt_id
)
BEGIN SELECT RAISE(ABORT, 'online dispatch issuance evidence is unauthorized'); END;
CREATE TRIGGER provider_online_dispatch_issuance_evidence_immutable
BEFORE UPDATE ON provider_online_dispatch_issuance_evidence
BEGIN SELECT RAISE(ABORT, 'online dispatch issuance evidence is immutable'); END;
CREATE TRIGGER provider_online_dispatch_issuance_evidence_no_delete
BEFORE DELETE ON provider_online_dispatch_issuance_evidence
BEGIN SELECT RAISE(ABORT, 'online dispatch issuance evidence is permanent'); END;
CREATE TRIGGER provider_online_dispatch_claim_provider_insert_authorized
BEFORE INSERT ON provider_online_dispatch_claim_providers
WHEN NOT EXISTS(
    SELECT 1 FROM provider_execution_admissions admission
    JOIN provider_online_dispatch_issuance_evidence evidence
      ON evidence.dispatch_attempt_id = admission.dispatch_attempt_id
    WHERE admission.dispatch_attempt_id = NEW.dispatch_attempt_id
      AND evidence.provider_id = NEW.provider_id
)
BEGIN SELECT RAISE(ABORT, 'online dispatch claim provider is unauthorized'); END;
CREATE TRIGGER provider_online_dispatch_claim_provider_immutable
BEFORE UPDATE ON provider_online_dispatch_claim_providers
BEGIN SELECT RAISE(ABORT, 'online dispatch claim provider is immutable'); END;
CREATE TRIGGER provider_online_dispatch_claim_provider_no_delete
BEFORE DELETE ON provider_online_dispatch_claim_providers
BEGIN SELECT RAISE(ABORT, 'online dispatch claim provider is permanent'); END;
CREATE TRIGGER provider_online_credential_effect_binding_insert_current
BEFORE INSERT ON provider_online_credential_effect_bindings
WHEN NOT EXISTS(
    SELECT 1
    FROM provider_effect_starts effect
    JOIN provider_execution_admissions admission
      ON admission.dispatch_attempt_id = effect.dispatch_attempt_id
    JOIN provider_online_dispatch_claim_providers claim_provider
      ON claim_provider.dispatch_attempt_id = admission.dispatch_attempt_id
    JOIN provider_runtime_authority_state runtime ON runtime.id = 1
    JOIN provider_credential_authority_heads head ON head.provider_id = NEW.provider_id
    JOIN provider_credential_versions mirror
      ON mirror.provider_id = NEW.provider_id
     AND mirror.credential_version = NEW.active_credential_version
     AND mirror.ref_digest = NEW.active_ref_digest
    WHERE effect.dispatch_attempt_id = NEW.dispatch_attempt_id
      AND runtime.active = 1
      AND runtime.expected_generation = runtime.lease_generation
      AND runtime.expected_generation = admission.generation
      AND runtime.expected_generation = NEW.launch_generation
      AND runtime.expected_fencing_token = runtime.lease_fencing_token
      AND runtime.expected_fencing_token = admission.fencing_token
      AND claim_provider.provider_id = NEW.provider_id
      AND head.lifecycle_revision = NEW.lifecycle_revision
      AND head.credential_fence = NEW.credential_fence
      AND head.active_credential_version = NEW.active_credential_version
      AND head.active_ref_digest = NEW.active_ref_digest
      AND head.hard_fence_disposition IS NULL
      AND head.release_migration_state IN ('NONE', 'CLEARED')
      AND mirror.lifecycle_state = 'ACTIVE'
      AND mirror.revocation_fence < mirror.lease_fencing_token
      AND mirror.lease_expires_at > effect.effect_started_at
)
BEGIN SELECT RAISE(ABORT, 'online credential effect binding is stale or fenced'); END;
CREATE TRIGGER provider_online_credential_effect_binding_immutable
BEFORE UPDATE ON provider_online_credential_effect_bindings
BEGIN SELECT RAISE(ABORT, 'online credential effect binding is immutable'); END;
CREATE TRIGGER provider_online_credential_effect_binding_no_delete
BEFORE DELETE ON provider_online_credential_effect_bindings
BEGIN SELECT RAISE(ABORT, 'online credential effect binding is permanent'); END;
"#;

pub(super) fn apply_v26_migration(conn: &Connection) -> SqliteResult<()> {
    let transaction = Transaction::new_unchecked(conn, TransactionBehavior::Exclusive)?;
    transaction.execute_batch(MIGRATION_V26)?;
    install_missing_v12_fence_triggers(&transaction)?;
    transaction.execute("INSERT INTO schema_version (version) VALUES (26)", [])?;
    transaction.commit()
}
