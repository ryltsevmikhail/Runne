use serde::Deserialize;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Rc2 {
    schema_version: String,
    parent_candidate_sha256: String,
    unsigned_manifest_sha256: String,
    pre_sign_artifacts: Vec<ArtifactPlan>,
    signer: Identity,
    runner: Identity,
    reviewer: Identity,
    update_issuer: Identity,
    workflow_sha256: String,
    effect_namespace: String,
    effect_generation: u64,
    valid_from: u64,
    expires_at: u64,
    revocation_epoch: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ArtifactPlan {
    artifact_slot_id: String,
    platform: String,
    operation: String,
    expected_artifact_sha256: String,
    expected_artifact_length: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Identity {
    #[serde(rename = "principal_id")]
    principal: String,
    #[serde(rename = "account_id")]
    account: String,
    #[serde(rename = "lane_id")]
    lane: String,
    #[serde(rename = "key_id")]
    key: String,
    #[serde(rename = "signature_profile_id")]
    signature_profile: String,
}

pub fn valid(value: &Rc2) -> bool {
    value.schema_version == "runne.release.rc2-signing-authorization/1"
        && value.valid_from < value.expires_at
        && value.revocation_epoch > 0
        && value.effect_generation > 0
        && digests(&[
            &value.parent_candidate_sha256,
            &value.unsigned_manifest_sha256,
            &value.workflow_sha256,
        ])
        && id(&value.effect_namespace)
        && exact_plan(&value.pre_sign_artifacts)
        && identities_distinct(&[
            &value.signer,
            &value.runner,
            &value.reviewer,
            &value.update_issuer,
        ])
}

fn exact_plan(plan: &[ArtifactPlan]) -> bool {
    plan.len() == 3
        && matches!(
            plan,
            [
                ArtifactPlan { artifact_slot_id, platform, .. },
                ArtifactPlan { artifact_slot_id: deb, platform: deb_platform, .. },
                ArtifactPlan { artifact_slot_id: windows, platform: windows_platform, .. },
            ] if artifact_slot_id == "linux-appimage" && platform == "linux"
                && deb == "linux-deb" && deb_platform == "linux"
                && windows == "windows-installer-unsigned" && windows_platform == "windows"
        )
        && plan.iter().all(|artifact| {
            artifact.operation == "native_sign"
                && id(&artifact.artifact_slot_id)
                && artifact.expected_artifact_length > 0
                && artifact_identity(artifact)
        })
}

fn artifact_identity(artifact: &ArtifactPlan) -> bool {
    digests(&[&artifact.expected_artifact_sha256])
}

fn identities_distinct(identities: &[&Identity]) -> bool {
    distinct(identities, |value| &value.principal)
        && distinct(identities, |value| &value.account)
        && distinct(identities, |value| &value.lane)
        && distinct(identities, |value| &value.key)
        && distinct(identities, |value| &value.signature_profile)
}

fn distinct<'a>(
    identities: &[&'a Identity],
    dimension: impl Fn(&'a Identity) -> &'a String,
) -> bool {
    let values = identities
        .iter()
        .map(|identity| dimension(identity))
        .collect::<std::collections::BTreeSet<_>>();
    values.len() == identities.len() && values.into_iter().all(|value| id(value))
}

fn id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .next()
            .is_some_and(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'_' | b'-')
        })
}

fn digests(values: &[&str]) -> bool {
    values.iter().all(|value| {
        value.len() == 64
            && value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    })
}
