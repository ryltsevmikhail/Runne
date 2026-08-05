from .models import CandidateIdentity, ValidatedCandidate


def candidate_identity(candidate: ValidatedCandidate) -> CandidateIdentity:
    if not isinstance(candidate, ValidatedCandidate):
        raise ValueError("invalid validated candidate")
    identity = candidate.candidate
    return CandidateIdentity(
        relative_name=identity.relative_name,
        tree_sha256=identity.tree_sha256,
        main_sha256=candidate.main.sha256,
        daemon_sha256=candidate.daemon.sha256,
        release_candidate_sha256=identity.release_candidate_sha256,
        app_entitlements_sha256=candidate.app_entitlements.sha256,
        daemon_entitlements_sha256=candidate.daemon_entitlements.sha256,
    )
