"""Small authenticated-result projections for Windows attestation tests."""

from __future__ import annotations

from scripts.rc0_policy.platform_attestation_profiles import AttestationGateBinding


WINDOWS_CONTROLS = (
    "windows_owner_acl", "windows_owner_dacl", "windows_reparse_safe",
    "windows_appcontainer", "windows_job_object_cleanup",
    "windows_descendant_cleanup", "windows_direct_egress_denial",
)
OTHER_CONTROLS = (
    "linux_protected_transport", "linux_landlock", "linux_seccomp",
    "linux_cgroups_v2", "linux_descendant_cleanup", "linux_direct_egress_denial",
    "macos_protected_transport", "macos_cleanup", "macos_direct_egress_denial",
    "macos_no_login_keychain", "macos_no_ssh_material", "macos_no_workspace",
    "macos_no_credential_environment", "macos_no_inherited_handles",
)
def windows_controls(*, failed: str | None = None, not_applicable: str | None = None) -> tuple[dict[str, str], ...]:
    rows = []
    for control_id in sorted((*WINDOWS_CONTROLS, *OTHER_CONTROLS)):
        result = "PASS" if control_id in WINDOWS_CONTROLS else "NOT_APPLICABLE"
        if control_id == failed: result = "FAILED"
        if control_id == not_applicable: result = "NOT_APPLICABLE"
        rows.append({"control_id": control_id, "result": result})
    return tuple(rows)


def windows_binding(mapping: object, scope_id: str = "windows-11-24h2-x86_64-production") -> AttestationGateBinding:
    return AttestationGateBinding("gocode", mapping.envelope_sha256, "b" * 64, "c" * 64, scope_id)
