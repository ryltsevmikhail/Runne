use super::policy;

#[test]
#[ignore = "read-only current-host PAM policy qualification; no authentication is attempted"]
fn current_arch_system_auth_policy_is_reviewed_and_safe() {
    policy::qualify().expect("current host matches a reviewed Arch system-auth policy");
}

const CONFIG_COUNT: usize = 4;

fn reviewed_set(profile: usize) -> (Vec<u8>, Vec<Vec<u8>>) {
    let system_auth = policy::test_profile_fixture(profile);
    let configs = (0..CONFIG_COUNT)
        .map(|index| policy::test_config_fixture(profile, index))
        .collect();
    (system_auth, configs)
}

fn slices(configs: &[Vec<u8>]) -> Vec<&[u8]> {
    configs.iter().map(Vec::as_slice).collect()
}

fn accepted(system_auth: &[u8], configs: &[Vec<u8>]) -> bool {
    policy::test_set_is_reviewed(system_auth, &slices(configs))
}

fn mutated_set(profile: usize, config_index: usize, replacement: &[u8]) -> (Vec<u8>, Vec<Vec<u8>>) {
    let (system_auth, mut configs) = reviewed_set(profile);
    configs[config_index] = replacement.to_vec();
    (system_auth, configs)
}

#[test]
fn both_reviewed_profiles_qualify_as_whole_sets() {
    assert_eq!(policy::test_profile_ids().len(), 2);
    for profile in 0..policy::test_profile_ids().len() {
        let (system_auth, configs) = reviewed_set(profile);
        assert!(
            accepted(&system_auth, &configs),
            "profile {} must qualify as a whole set",
            policy::test_profile_ids()[profile]
        );
    }
}

#[test]
fn legacy_comments_and_blank_lines_normalize_away() {
    let (system_auth, mut configs) = reviewed_set(0);
    configs[0] = b"# reviewed defaults\ndeny = 10\n\n# tail\n".to_vec();
    assert!(accepted(&system_auth, &configs));
}

#[test]
fn hybrid_mixes_of_profiles_are_rejected_per_changed_file() {
    let legacy = reviewed_set(0);
    let stock = reviewed_set(1);
    // Профили различаются только system-auth, faillock.conf и pam_env.conf;
    // time.conf и /etc/environment у обоих пусты, поэтому замена этих файлов
    // совпадающими ожиданиями гибридом не является и набор остаётся валидным.
    for config_index in 0..CONFIG_COUNT {
        if legacy.1[config_index] == stock.1[config_index] {
            continue;
        }
        let (stock_auth, mixed) = mutated_set(1, config_index, &legacy.1[config_index]);
        assert!(
            !accepted(&stock_auth, &mixed),
            "stock set with legacy config {config_index} must be rejected"
        );
        let (legacy_auth, mixed) = mutated_set(0, config_index, &stock.1[config_index]);
        assert!(
            !accepted(&legacy_auth, &mixed),
            "legacy set with stock config {config_index} must be rejected"
        );
    }
    assert!(!accepted(&stock.0, &legacy.1));
    assert!(!accepted(&legacy.0, &stock.1));
}

#[test]
fn unknown_stacks_modules_and_options_are_rejected() {
    for profile in 0..policy::test_profile_ids().len() {
        let base = policy::test_profile_fixture(profile);
        for changed in [
            String::from_utf8_lossy(&base).replace(
                "pam_unix.so try_first_pass nullok\n",
                "pam_unix.so try_first_pass nullok custom_unknown_option\n",
            ),
            String::from_utf8_lossy(&base)
                .replace("auth required pam_env.so", "auth include common-auth"),
            String::from_utf8_lossy(&base).replace(
                "account required pam_time.so",
                "account substack other-account",
            ),
        ] {
            let (_, configs) = reviewed_set(profile);
            assert!(!accepted(changed.as_bytes(), &configs));
        }
    }
}

#[test]
fn extra_missing_reordered_and_control_changes_are_rejected() {
    for profile in 0..policy::test_profile_ids().len() {
        let base = policy::test_profile_fixture(profile);
        let text = String::from_utf8_lossy(&base).into_owned();
        let reordered = text.replacen(
            "auth optional pam_permit.so\nauth required pam_env.so",
            "auth required pam_env.so\nauth optional pam_permit.so",
            1,
        );
        let missing = text.replacen("account required pam_time.so\n", "", 1);
        let extra = format!("{text}session optional pam_console.so\n");
        let control = text.replacen(
            "auth [success=1 default=bad] pam_unix.so",
            "auth sufficient pam_unix.so",
            1,
        );
        for changed in [reordered, missing, extra, control] {
            let (_, configs) = reviewed_set(profile);
            assert!(changed != text, "mutation must change the fixture");
            assert!(!accepted(changed.as_bytes(), &configs));
        }
    }
}

#[test]
fn weaker_or_unreviewed_faillock_and_env_settings_are_rejected() {
    let stock_auth = policy::test_profile_fixture(1);
    let stock_configs = reviewed_set(1).1;
    for unreviewed in [
        &b"deny = 3\n"[..],
        &b"deny = 100\n"[..],
        &b"unlock_time = 30\n"[..],
        &b"even_deny_root\n"[..],
        &b"deny = 10\n"[..],
    ] {
        let mut configs = stock_configs.clone();
        configs[0] = unreviewed.to_vec();
        assert!(!accepted(&stock_auth, &configs));
    }
    let legacy_auth = policy::test_profile_fixture(0);
    let mut legacy_configs = reviewed_set(0).1;
    legacy_configs[0] = b"deny = 100\nunlock_time = 1\n".to_vec();
    assert!(!accepted(&legacy_auth, &legacy_configs));
    let weaker_inline = String::from_utf8_lossy(&legacy_auth)
        .replace("deny=10 unlock_time=120", "deny=100 unlock_time=1");
    assert_ne!(weaker_inline.as_bytes(), legacy_auth.as_slice());
    assert!(!accepted(weaker_inline.as_bytes(), &reviewed_set(0).1));
    let mut env_mixed = stock_configs.clone();
    env_mixed[1] = b"PATH DEFAULT=/tmp\n".to_vec();
    assert!(!accepted(&stock_auth, &env_mixed));
    let mut time_mixed = stock_configs.clone();
    time_mixed[2] = b"login;tty*;*;Al0000-2400\n".to_vec();
    assert!(!accepted(&stock_auth, &time_mixed));
    let mut environment_mixed = stock_configs;
    environment_mixed[3] = b"PATH=/tmp\n".to_vec();
    assert!(!accepted(&stock_auth, &environment_mixed));
}

#[test]
fn relevant_configuration_semantics_and_fingerprints_are_exact() {
    assert!(policy::test_same_fingerprint([1; 32], [1; 32]));
    assert!(!policy::test_same_fingerprint([1; 32], [2; 32]));
}

#[test]
fn user_writable_or_non_root_paths_are_rejected() {
    assert!(policy::test_secure_mode(0, 0o644));
    assert!(!policy::test_secure_mode(1000, 0o644));
    assert!(!policy::test_secure_mode(0, 0o666));
    assert!(!policy::test_secure_mode(0, 0o775));
}

#[test]
fn capture_fails_closed_under_untrusted_ancestors() {
    // Интеграционное свойство traversal на КОМБИНИРОВАННОЙ негативной
    // фиксуре: предок с group-write (0o770), а при non-root-раннере ещё и
    // с uid != 0. Захват fail-closed при любом пользователе/umask, но
    // регрессия отдельного предиката (например, только проверки режима)
    // может быть замаскирована другим нарушенным условием (владельцем);
    // независимого доказательства каждого предиката тест не даёт.
    // Положительный root-owned путь — ignored-тест реального хоста
    // (только чтение); логика предиката uid/режим — test_secure_mode.
    use std::fs::Permissions;
    use std::os::unix::fs::PermissionsExt;
    let directory = tempfile::tempdir().expect("tempdir");
    std::fs::set_permissions(directory.path(), Permissions::from_mode(0o770))
        .expect("group-writable ancestor");
    let path = directory.path().join("policy");
    std::fs::write(&path, b"policy").expect("file");
    assert!(policy::test_capture(path.to_str().expect("path")).is_err());
}

#[test]
fn insecure_leaf_metadata_fixtures_fail_closed_combined() {
    // КОМБИНИРОВАННЫЕ негативные фиксуры лист-метаданных (без root и без
    // изменений хоста): каждая запись нарушает НЕСКОЛЬКО предикатов сразу
    // (non-root uid у создаваемых файлов; режим 0o666/0o770; symlink и
    // не-тот тип). Тест доказывает fail-closed на таких записях, но НЕ
    // независимость отдельных проверок require_secure_file/directory:
    // при non-root раннере uid != 0 маскирует регрессию проверки режима
    // или типа; symlink на Linux всегда имеет режим 0777, поэтому даже
    // под root режим маскирует классификацию symlink. Отдельные тесты
    // test_secure_mode проверяют логику предиката, но НЕ подтверждают,
    // что реальные guards вызывают её независимо. Независимое покрытие
    // каждого предиката реальными метаданными потребовало бы root-owned
    // фикстур (root на хосте не используется).
    use std::fs::Permissions;
    use std::os::unix::fs::PermissionsExt;
    let directory = tempfile::tempdir().expect("tempdir");
    std::fs::set_permissions(directory.path(), Permissions::from_mode(0o770)).expect("dir mode");

    let file_path = directory.path().join("leaf");
    std::fs::write(&file_path, b"leaf").expect("file");
    std::fs::set_permissions(&file_path, Permissions::from_mode(0o666)).expect("file mode");
    let file_metadata = std::fs::symlink_metadata(&file_path).expect("file metadata");
    assert!(policy::test_require_secure_file(&file_metadata).is_err());
    assert!(policy::test_require_secure_directory(&file_metadata).is_err());

    let file_link = directory.path().join("leaf-link");
    std::os::unix::fs::symlink(&file_path, &file_link).expect("file symlink");
    let link_metadata = std::fs::symlink_metadata(&file_link).expect("symlink metadata");
    assert!(policy::test_require_secure_file(&link_metadata).is_err());
    assert!(policy::test_require_secure_directory(&link_metadata).is_err());

    let dir_metadata = std::fs::symlink_metadata(directory.path()).expect("dir metadata");
    assert!(policy::test_require_secure_file(&dir_metadata).is_err());
    assert!(policy::test_require_secure_directory(&dir_metadata).is_err());

    let dir_link = directory.path().join("dir-link");
    std::os::unix::fs::symlink(directory.path(), &dir_link).expect("dir symlink");
    let dir_link_metadata = std::fs::symlink_metadata(&dir_link).expect("dir link metadata");
    assert!(policy::test_require_secure_file(&dir_link_metadata).is_err());
    assert!(policy::test_require_secure_directory(&dir_link_metadata).is_err());
}

#[test]
fn active_line_normalization_preserves_options_and_order() {
    assert_eq!(
        policy::test_active_lines(b"# comment\nauth  required pam_unix.so nullok\n\n")
            .expect("UTF-8 config"),
        ["auth required pam_unix.so nullok"]
    );
    assert!(policy::test_active_lines(&[0xff]).is_err());
}
