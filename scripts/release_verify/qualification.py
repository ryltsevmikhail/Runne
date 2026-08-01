def validate_qualification(
    qualification_state,
    evidence,
    evidence_kinds,
    lane_slots,
    platform_artifacts,
    review_identities,
    hosted_kinds,
):
    if qualification_state == "draft":
        if evidence or any(slot["status"] != "planned" for slots in lane_slots.values() for slot in slots.values()):
            raise ValueError("invalid draft state")
    assembled_kinds = {"package", "checksums", "provenance-attestation", "sbom"}
    verified_kinds = assembled_kinds | hosted_kinds | {"advisory", "license", "secret-scan", "performance", "soak", "chaos", "fresh-install", "upgrade", "rollback", "compatibility", "phase6b-native-certificate", "phase8-compatibility", "phase9-operations"}
    if qualification_state == "assembled":
        if any(slot["status"] != "planned" for slots in lane_slots.values() for slot in slots.values()):
            raise ValueError("invalid assembled state")
        if not evidence_kinds.issubset(assembled_kinds):
            raise ValueError("invalid assembled evidence")
        for platform in platform_artifacts:
            if not {"package", "checksums", "provenance-attestation", "sbom"}.issubset({record["kind"] for record in evidence if record["platform"] == platform}):
                raise ValueError("incomplete assembled state")
    if qualification_state in {"verified", "review-pending", "approved"}:
        if any(slot["status"] != "actual" for slots in lane_slots.values() for slot in slots.values()):
            raise ValueError("incomplete verified state")
        if not verified_kinds.issubset(evidence_kinds):
            raise ValueError("incomplete verified evidence")
        for platform in platform_artifacts:
            if not assembled_kinds.issubset({record["kind"] for record in evidence if record["platform"] == platform}):
                raise ValueError("missing assembled evidence for platform")
    if qualification_state == "verified" and not evidence_kinds.issubset(verified_kinds):
        raise ValueError("invalid verified evidence")
    if qualification_state in {"review-pending", "approved"} and "review-packet" not in evidence_kinds:
        raise ValueError("missing review packet")
    if qualification_state == "review-pending" and not evidence_kinds.issubset(verified_kinds | {"review-packet"}):
        raise ValueError("invalid pending-review evidence")
    if qualification_state == "blocked" and "blocked-gate" not in evidence_kinds:
        raise ValueError("blocked state requires blocked-gate evidence")
    if qualification_state == "approved":
        if not {"review-packet", "independent-final-review", "owner-approval"}.issubset(evidence_kinds) or not evidence_kinds.issubset(verified_kinds | {"review-packet", "independent-final-review", "owner-approval"}):
            raise ValueError("invalid approved evidence")
        if review_identities.get("independent-final-review") == review_identities.get("owner-approval"):
            raise ValueError("owner cannot independently final-review")
