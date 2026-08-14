"""Public fixture-only facade for post-RC0 platform policy verification."""

from __future__ import annotations

from scripts.rc0_policy.governance_status import parse_accepted_adr
from scripts.rc0_policy.platform_policy_errors import PolicyFailure


from scripts.rc0_policy.platform_policy_mapping import (  # noqa: E402
    ArtifactSlotPolicyRow, AuthorityRoleBinding, PlatformScopePolicyRow,
    HostPolicyRow, ProfileStatePolicyRow, Rc0TrustPolicyView, VerifiedMappingPolicy,
    fixture_verify_mapping_policy, verify_mapping_policy,
)
from scripts.rc0_policy.platform_policy_report import (  # noqa: E402
    ReportArtifactBinding, RequiredGateResultRow, VerifiedDeclaration,
    VerifiedReport, validate_report_against_policy, verify_qualified_declaration,
)

__all__ = (
    "ArtifactSlotPolicyRow", "AuthorityRoleBinding", "PlatformScopePolicyRow",
    "HostPolicyRow", "PolicyFailure", "ProfileStatePolicyRow",
    "Rc0TrustPolicyView", "ReportArtifactBinding", "RequiredGateResultRow",
    "VerifiedDeclaration", "VerifiedMappingPolicy", "VerifiedReport",
    "parse_accepted_adr", "validate_report_against_policy",
    "fixture_verify_mapping_policy", "verify_mapping_policy",
    "verify_qualified_declaration",
)
