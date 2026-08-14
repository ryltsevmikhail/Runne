"""Deferred adapter for the post-RC0 platform-claim migration validator."""

from scripts.rc0_policy.claim_migration import ClaimMigrationFailure, validate_claim_registry


def validate_platform_scope_claims(
    repo_root, registry_raw, base_document_universe_raw, classified_delta_raw,
    composed_document_universe_raw,
):
    try:
        return validate_claim_registry(
            repo_root, registry_raw, base_document_universe_raw,
            classified_delta_raw, composed_document_universe_raw,
        )
    except ClaimMigrationFailure as error:
        err(f"Platform scope claim migration: {error}")
        return ()
