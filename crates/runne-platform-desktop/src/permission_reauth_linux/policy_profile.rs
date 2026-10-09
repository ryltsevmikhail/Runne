const PAM_PROFILE: &[&str] = &[
    "auth required pam_faillock.so preauth silent deny=10 unlock_time=120",
    "-auth [success=2 default=ignore] pam_systemd_home.so",
    "auth [success=1 default=bad] pam_unix.so try_first_pass nullok",
    "auth [default=die] pam_faillock.so authfail deny=10 unlock_time=120",
    "auth optional pam_permit.so",
    "auth required pam_env.so",
    "auth required pam_faillock.so authsucc",
    "-account [success=1 default=ignore] pam_systemd_home.so",
    "account required pam_unix.so",
    "account optional pam_permit.so",
    "account required pam_time.so",
    "-password [success=1 default=ignore] pam_systemd_home.so",
    "password required pam_unix.so try_first_pass nullok shadow",
    "password optional pam_permit.so",
    "-session optional pam_systemd_home.so",
    "session required pam_limits.so",
    "session required pam_unix.so",
    "session optional pam_permit.so",
];

pub(super) const AUTH_CONFIGS: &[(&str, &[&str])] = &[
    ("/etc/security/faillock.conf", &["deny = 10"]),
    (
        "/etc/security/pam_env.conf",
        &[
            "PATH DEFAULT=/usr/local/sbin:/usr/local/bin:/usr/bin:@{HOME}/.local/share/mise/shims:@{HOME}/.local/bin",
        ],
    ),
    ("/etc/security/time.conf", &[]),
    ("/etc/environment", &[]),
];

pub(super) const MODULES: &[&str] = &[
    "pam_faillock.so",
    "pam_systemd_home.so",
    "pam_unix.so",
    "pam_permit.so",
    "pam_env.so",
    "pam_time.so",
    "pam_limits.so",
];

pub(super) fn require_pam_profile(contents: &[u8]) -> Result<(), ()> {
    require_lines(contents, PAM_PROFILE)
}

pub(super) fn require_auth_config(index: usize, contents: &[u8]) -> Result<(), ()> {
    let (_, expected) = AUTH_CONFIGS.get(index).ok_or(())?;
    require_lines(contents, expected)
}

#[cfg(test)]
pub(super) fn reviewed_profile_fixture() -> Vec<u8> {
    PAM_PROFILE.join("\n").into_bytes()
}

fn require_lines(contents: &[u8], expected: &[&str]) -> Result<(), ()> {
    let actual = active_lines(contents)?;
    let expected: Vec<String> = expected.iter().map(|line| (*line).to_owned()).collect();
    (actual == expected).then_some(()).ok_or(())
}

pub(super) fn active_lines(contents: &[u8]) -> Result<Vec<String>, ()> {
    let text = std::str::from_utf8(contents).map_err(|_| ())?;
    Ok(text
        .lines()
        .filter_map(|line| {
            let active = line.split('#').next().unwrap_or_default();
            let normalized = active.split_whitespace().collect::<Vec<_>>().join(" ");
            (!normalized.is_empty()).then_some(normalized)
        })
        .collect())
}
