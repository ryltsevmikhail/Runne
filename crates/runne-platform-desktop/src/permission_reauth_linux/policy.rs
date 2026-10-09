#[path = "policy_files.rs"]
mod policy_files;
#[path = "policy_profile.rs"]
mod policy_profile;

const MAX_CONFIG_BYTES: u64 = 1024 * 1024;
const MAX_MODULE_BYTES: u64 = 64 * 1024 * 1024;

pub(super) struct QualifiedPolicy {
    digest: [u8; 32],
}

impl QualifiedPolicy {
    pub(super) const fn digest(&self) -> [u8; 32] {
        self.digest
    }
}

pub(super) fn qualify() -> Result<QualifiedPolicy, ()> {
    let mut entries = Vec::new();
    let pam_config = policy_files::capture("/etc/pam.d/system-auth", MAX_CONFIG_BYTES)?;
    policy_profile::require_pam_profile(&pam_config.contents)?;
    entries.push(pam_config);
    for (index, (path, _)) in policy_profile::AUTH_CONFIGS.iter().enumerate() {
        let captured = policy_files::capture(path, MAX_CONFIG_BYTES)?;
        policy_profile::require_auth_config(index, &captured.contents)?;
        entries.push(captured);
    }
    for module in policy_profile::MODULES {
        let path = format!("/usr/lib/security/{module}");
        entries.push(policy_files::capture(&path, MAX_MODULE_BYTES)?);
    }
    Ok(QualifiedPolicy {
        digest: policy_files::fingerprint(&entries),
    })
}

pub(super) fn verify_unchanged(expected: &QualifiedPolicy) -> Result<(), ()> {
    let current = qualify()?;
    policy_files::same_fingerprint(expected.digest, current.digest)
        .then_some(())
        .ok_or(())
}

#[cfg(test)]
pub(super) fn test_active_lines(contents: &[u8]) -> Result<Vec<String>, ()> {
    policy_profile::active_lines(contents)
}

#[cfg(test)]
pub(super) fn test_profile_is_reviewed(contents: &[u8]) -> bool {
    policy_profile::require_pam_profile(contents).is_ok()
}

#[cfg(test)]
pub(super) fn test_profile_fixture() -> Vec<u8> {
    policy_profile::reviewed_profile_fixture()
}

#[cfg(test)]
pub(super) fn test_config_is_reviewed(index: usize, contents: &[u8]) -> bool {
    policy_profile::require_auth_config(index, contents).is_ok()
}

#[cfg(test)]
pub(super) fn test_same_fingerprint(expected: [u8; 32], current: [u8; 32]) -> bool {
    policy_files::same_fingerprint(expected, current)
}

#[cfg(test)]
pub(super) const fn test_secure_mode(uid: u32, mode: u32) -> bool {
    policy_files::test_secure_mode(uid, mode)
}
