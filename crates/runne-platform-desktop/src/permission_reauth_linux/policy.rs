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

/// Захватывает полный набор policy-файлов (system-auth, все security-конфиги,
/// модули) с прежними проверками владения/symlink/режима/TOCTOU и принимает
/// его только при точном совпадении целиком с одним из reviewed-профилей.
pub(super) fn qualify() -> Result<QualifiedPolicy, ()> {
    let mut entries = Vec::new();
    entries.push(policy_files::capture(
        "/etc/pam.d/system-auth",
        MAX_CONFIG_BYTES,
    )?);
    let mut auth_configs = Vec::new();
    for path in policy_profile::auth_config_paths() {
        auth_configs.push(policy_files::capture(path, MAX_CONFIG_BYTES)?);
    }
    let contents: Vec<&[u8]> = auth_configs
        .iter()
        .map(|entry| entry.contents.as_slice())
        .collect();
    policy_profile::require_reviewed_set(&entries[0].contents, &contents)?;
    entries.extend(auth_configs);
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
pub(super) fn test_set_is_reviewed(system_auth: &[u8], auth_configs: &[&[u8]]) -> bool {
    policy_profile::require_reviewed_set(system_auth, auth_configs).is_ok()
}

#[cfg(test)]
pub(super) fn test_capture(path: &str) -> Result<(), ()> {
    policy_files::capture(path, MAX_CONFIG_BYTES).map(|_| ())
}

#[cfg(test)]
pub(super) fn test_profile_fixture(index: usize) -> Vec<u8> {
    policy_profile::profile_fixture(index)
}

#[cfg(test)]
pub(super) fn test_config_fixture(profile_index: usize, config_index: usize) -> Vec<u8> {
    policy_profile::config_fixture(profile_index, config_index)
}

#[cfg(test)]
pub(super) fn test_profile_ids() -> Vec<&'static str> {
    policy_profile::profile_ids()
}

#[cfg(test)]
pub(super) fn test_same_fingerprint(expected: [u8; 32], current: [u8; 32]) -> bool {
    policy_files::same_fingerprint(expected, current)
}

#[cfg(test)]
pub(super) const fn test_secure_mode(uid: u32, mode: u32) -> bool {
    policy_files::test_secure_mode(uid, mode)
}

#[cfg(test)]
pub(super) fn test_require_secure_file(metadata: &std::fs::Metadata) -> Result<(), ()> {
    policy_files::test_require_secure_file(metadata)
}

#[cfg(test)]
pub(super) fn test_require_secure_directory(metadata: &std::fs::Metadata) -> Result<(), ()> {
    policy_files::test_require_secure_directory(metadata)
}
