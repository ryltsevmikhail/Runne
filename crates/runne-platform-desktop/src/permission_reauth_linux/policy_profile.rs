//! Точные reviewed-профили хостовой PAM-политики. Каждый профиль — полный
//! когерентный набор: нормализованные активные строки `/etc/pam.d/system-auth`
//! плюс ожидания для каждого файла из `AUTH_CONFIG_PATHS` (по индексу).
//! Набор принимается только целиком; смешение файлов разных профилей
//! (гибриды) отклоняется в `require_reviewed_set`.

const AUTH_CONFIG_PATHS: &[&str] = &[
    "/etc/security/faillock.conf",
    "/etc/security/pam_env.conf",
    "/etc/security/time.conf",
    "/etc/environment",
];

/// Профиль `legacy-2026-10-07`: состояние bigpc до переустановки ОС
/// 2026-10-12, прошло reviewed-gate 2026-10-07/08. faillock: `deny=10`,
/// `unlock_time=120` (inline и в faillock.conf), preauth silent.
const LEGACY_PAM_PROFILE: &[&str] = &[
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

const LEGACY_AUTH_CONFIG_LINES: &[&[&str]] = &[
    &["deny = 10"],
    &[
        "PATH DEFAULT=/usr/local/sbin:/usr/local/bin:/usr/bin:@{HOME}/.local/share/mise/shims:@{HOME}/.local/bin",
    ],
    &[],
    &[],
];

/// Профиль `stock-pambase-20260616-1-pam-1.7.3-1`: литералы активных строк,
/// наблюдаемых на хосте 2026-10-14 для пакетных умолчаний pambase
/// 20260616-1 + pam 1.7.3-1 (нулевые активные строки во всех четырёх
/// security-конфигах). Имя профиля — provenance наблюдения, НЕ enforced
/// ограничение версий: гейт сверяет ТОЛЬКО активные строки конфигов (любые
/// иные — fail-closed), модулям доверяет в рамках существующего boundary
/// доверенных root-owned файлов; хэши модулей входят лишь в digest
/// церемонии (детекция дрейфа mid-ceremony), baseline-allowlist
/// версий/хэшей отсутствует. Семантика faillock — компилируемые умолчания
/// `pam_faillock` 1.7.3-1: `deny=3`, `fail_interval=900`, `unlock_time=600`,
/// root не лочится (`even_deny_root` отсутствует), preauth не silent.
/// Обновление пакетов ДО церемонии с неизменными активными строками может
/// быть принято даже при изменившихся компилируемых умолчаниях; гарантии
/// fail-closed на будущие обновления нет (риск и границы доверия —
/// docs/05-security/PAM_REAUTH_PROFILES.md).
const STOCK_PAM_PROFILE: &[&str] = &[
    "auth required pam_faillock.so preauth",
    "-auth [success=2 default=ignore] pam_systemd_home.so",
    "auth [success=1 default=bad] pam_unix.so try_first_pass nullok",
    "auth [default=die] pam_faillock.so authfail",
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

const STOCK_AUTH_CONFIG_LINES: &[&[&str]] = &[&[], &[], &[], &[]];

/// Модули обоих reviewed-профилей; наличие и безопасность каждого файла
/// проверяет захват в `policy.rs` (root-owned, без symlink, без group/world
/// write), отсутствие файла — отказ.
pub(super) const MODULES: &[&str] = &[
    "pam_faillock.so",
    "pam_systemd_home.so",
    "pam_unix.so",
    "pam_permit.so",
    "pam_env.so",
    "pam_time.so",
    "pam_limits.so",
];

pub(super) struct ReviewedProfile {
    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "Идентификатор профиля читается тестами reviewed-набора."
        )
    )]
    pub(super) id: &'static str,
    pub(super) pam_profile: &'static [&'static str],
    /// Индекс выровнен с `AUTH_CONFIG_PATHS`.
    auth_config_lines: &'static [&'static [&'static str]],
}

pub(super) const PROFILES: &[ReviewedProfile] = &[
    ReviewedProfile {
        id: "legacy-2026-10-07",
        pam_profile: LEGACY_PAM_PROFILE,
        auth_config_lines: LEGACY_AUTH_CONFIG_LINES,
    },
    ReviewedProfile {
        id: "stock-pambase-20260616-1-pam-1.7.3-1",
        pam_profile: STOCK_PAM_PROFILE,
        auth_config_lines: STOCK_AUTH_CONFIG_LINES,
    },
];

/// Требует, чтобы весь захваченный набор (system-auth + все файлы
/// `AUTH_CONFIG_PATHS` по порядку) точно совпал хотя бы с одним полным
/// профилем. Гибрид (файлы разных профилей) не совпадает ни с одним
/// целиком и отклоняется.
pub(super) fn require_reviewed_set(system_auth: &[u8], auth_configs: &[&[u8]]) -> Result<(), ()> {
    PROFILES
        .iter()
        .any(|profile| profile_matches(profile, system_auth, auth_configs))
        .then_some(())
        .ok_or(())
}

fn profile_matches(profile: &ReviewedProfile, system_auth: &[u8], auth_configs: &[&[u8]]) -> bool {
    require_lines(system_auth, profile.pam_profile).is_ok()
        && auth_configs.len() == profile.auth_config_lines.len()
        && auth_configs
            .iter()
            .zip(profile.auth_config_lines)
            .all(|(actual, expected)| require_lines(actual, expected).is_ok())
}

pub(super) fn auth_config_paths() -> impl Iterator<Item = &'static str> {
    AUTH_CONFIG_PATHS.iter().copied()
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

#[cfg(test)]
pub(super) fn profile_fixture(index: usize) -> Vec<u8> {
    PROFILES
        .get(index)
        .map(|profile| profile.pam_profile.join("\n").into_bytes())
        .unwrap_or_default()
}

#[cfg(test)]
pub(super) fn config_fixture(profile_index: usize, config_index: usize) -> Vec<u8> {
    PROFILES
        .get(profile_index)
        .and_then(|profile| profile.auth_config_lines.get(config_index))
        .map(|lines| lines.join("\n").into_bytes())
        .unwrap_or_default()
}

#[cfg(test)]
pub(super) fn profile_ids() -> Vec<&'static str> {
    PROFILES.iter().map(|profile| profile.id).collect()
}
