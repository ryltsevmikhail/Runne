use crate::InspectedCanonicalPayload;
use crate::wire::semantics::ThresholdMetadataParts;

pub fn matches(
    metadata: &ThresholdMetadataParts,
    manifest: &InspectedCanonicalPayload,
    records: &[&InspectedCanonicalPayload],
) -> bool {
    let Some(facts) = manifest.release_facts() else {
        return false;
    };
    metadata
        .targets
        .iter()
        .zip(records)
        .zip([
            &facts.artifacts[0],
            &facts.artifacts[1],
            &facts.artifacts[4],
        ])
        .all(|((target, record), fact)| {
            let Some(record) = record.artifact_record() else {
                return false;
            };
            let expected_bundle_identity = &facts.bundle_identity;
            target.app_version == facts.app_version
                && target.release_sequence == facts.release_sequence
                && target.bundle_id == *expected_bundle_identity
                && target.slot == fact.artifact_slot_id
                && target.platform == fact.platform
                && target.architecture == fact.architecture
                && target.minimum_os
                    == (
                        fact.minimum_os_policy.policy_id.clone(),
                        fact.minimum_os_policy.policy_sha256.value(),
                    )
                && target.profiles
                    == fact
                        .profile_bindings
                        .iter()
                        .map(|profile| (profile.profile_id.clone(), profile.bundle_sha256.value()))
                        .collect::<Vec<_>>()
                && target.runtime
                    == (
                        facts.bundled_runtime.version.clone(),
                        facts.bundled_runtime.sha256.value(),
                    )
                && record.artifact_slot_id == target.slot
                && record.platform == target.platform
                && record.artifact == target.artifact
                && record.artifact_length == target.length
        })
}
