from .constants import OPERATION_KINDS

def finalize(block, state, fixture_only):
    lane_slots = state["lane_slots"]
    hosted_evidence = state["hosted_evidence"]
    evidence_kinds = state["evidence_kinds"]
    operation_evidence = state["operation_evidence"]
    phase_evidence = state["phase_evidence"]
    qualification_state = state["qualification_state"]
    # Evidence gates are deliberately evaluated even when local structural checks failed.
    hosted_complete = all(
        lane_slots.get(lane, {}).get(platform, {}).get("status") == "actual"
        for lane in ("pinned-1.97.1", "msrv-1.95.0") for platform in ("linux", "macos", "windows")
    )
    required_hosted_evidence = {
        (kind, lane, platform)
        for kind in ("hosted-build-test", "hosted-clippy", "hosted-rustdoc", "hosted-docs")
        for lane in ("pinned-1.97.1", "msrv-1.95.0")
        for platform in ("linux", "macos", "windows")
    }
    if not fixture_only or not hosted_complete or not required_hosted_evidence.issubset(hosted_evidence):
        block("hosted-platform-evidence")
    if not {"advisory", "license", "secret-scan", "sbom"}.issubset(evidence_kinds):
        block("security-evidence")
    if not {"performance", "soak", "chaos"}.issubset(evidence_kinds):
        block("performance-evidence")
    if not {"fresh-install", "upgrade", "rollback", "compatibility"}.issubset(evidence_kinds):
        block("compatibility")
    if not {
        (kind, platform)
        for kind in OPERATION_KINDS
        for platform in ("linux", "macos", "windows")
    }.issubset(operation_evidence):
        block("install-upgrade-rollback")
    for kind in ("phase6b-native-certificate", "phase8-compatibility", "phase9-operations"):
        if not {(kind, platform) for platform in ("linux", "macos", "windows")}.issubset(phase_evidence):
            block(kind)
    for kind in ("independent-final-review", "owner-approval"):
        if kind not in evidence_kinds:
            block(kind)
    if not fixture_only and qualification_state == "approved":
        block("approval-attestation")
    if qualification_state != "approved":
        block("qualification-state")
