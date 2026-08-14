"""Fail-closed bridge for the future production composed-universe verifier."""


def validate_post_rc0_composed_authority(snapshot, authority_context=None):
    """Reject composed routing until public production verification creates context."""
    del snapshot, authority_context
    raise ValueError("DOCS_COMPOSED_AUTHORITY_UNAVAILABLE")
