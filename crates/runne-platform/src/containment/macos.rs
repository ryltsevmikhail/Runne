//! macOS containment — fail-closed until a signed helper is qualified.
//!
//! Platform-specific OS APIs require `unsafe`; all unsafe blocks are isolated
//! in this module with safety comments.
#![allow(unsafe_code)]

mod profile;

pub use profile::MacOsSeatbeltProfileV1;

use super::{
    AttestationVerdict, ContainmentError, ContainmentRequest, NativeCertificate, RuntimeProbe,
};

/// Fail-closed macOS containment backend.
///
/// The Seatbelt profile builder and the signed helper exist, but no permit is
/// issued until the helper is qualified and the release gate consumes it.
pub struct MacOsContainment;

unsafe extern "C" {
    /// sandbox_init применяет Seatbelt profile к текущему процессу.
    /// Возвращает 0 при успехе, -1 при ошибке.
    fn sandbox_init(
        profile: *const libc::c_char,
        flags: u64,
        errorbuf: *mut *mut libc::c_char,
    ) -> libc::c_int;
}

/// Проверяет, можем ли мы загрузить libsandbox и применить
/// минимальный Seatbelt profile в дочернем процессе.
///
/// Это не production qualification — только проверка доступности API.
pub fn probe_sandbox_api() -> bool {
    // Минимальный profile: разрешаем всё (allow default).
    // Если sandbox_init успешен, API доступно.
    let profile = "(version 1)\n(debug deny)\n(allow default)\n\0";

    let pid = unsafe { libc::fork() };
    if pid < 0 {
        return false;
    }
    if pid == 0 {
        let mut errmsg: *mut libc::c_char = std::ptr::null_mut();
        let ret = unsafe { sandbox_init(profile.as_ptr() as *const libc::c_char, 0, &mut errmsg) };
        // Не освобождаем errmsg, так как дочерний процесс завершается.
        unsafe { libc::exit(if ret == 0 { 0 } else { 1 }) };
    }

    let mut status = 0;
    let waited = unsafe { libc::waitpid(pid, &mut status, 0) };
    waited == pid && libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0
}

impl MacOsContainment {
    /// Не предоставляет permit без сертифицированного native backend Phase 6B.
    pub fn attest(
        request: &ContainmentRequest,
        certificate: Option<&NativeCertificate>,
        probes: &[RuntimeProbe],
    ) -> Result<AttestationVerdict, ContainmentError> {
        let _ = (request, certificate, probes);
        Err(ContainmentError::BackendUnavailable)
    }

    /// Проверяет sandbox API, но production-бэкенд появится только после
    /// проверки signed helper с Developer ID.
    pub fn probe() -> Result<Self, ContainmentError> {
        // Реальный probe sandbox API выполняется, но containment backend
        // остаётся недоступен до завершения Phase 6B macOS.
        let _ = probe_sandbox_api();
        Err(ContainmentError::BackendUnavailable)
    }
}

#[cfg(test)]
#[path = "macos/helper_tests.rs"]
mod helper_tests;

#[cfg(test)]
mod tests {
    use std::process::Command;

    use super::*;

    /// Reports whether this process tree can apply a Seatbelt profile at all.
    ///
    /// Agent and CI sandboxes already confine the test process, and a nested
    /// profile cannot be applied from there. Apple's own `sandbox-exec` is the
    /// control: when it fails, the limitation is the environment, not the code.
    fn seatbelt_available() -> bool {
        Command::new("/usr/bin/sandbox-exec")
            .args(["-p", "(version 1)(allow default)", "/usr/bin/true"])
            .output()
            .is_ok_and(|output| output.status.success())
    }

    /// Возвращает путь к собранному `runne-sandbox-helper` binary.
    fn helper_binary_path() -> std::path::PathBuf {
        // Тест запускается из `crates/runne-platform`, поэтому workspace target
        // находится в `../../target/debug`.
        std::env::current_dir()
            .expect("current dir")
            .join("../../target/debug/runne-sandbox-helper")
    }

    fn build_helper() {
        let status = Command::new("cargo")
            .args(["build", "-p", "runne-sandbox-helper"])
            .status()
            .expect("spawn cargo build");
        assert!(status.success(), "cargo build runne-sandbox-helper failed");
    }

    /// Валидные codesigning identity из keychain пользователя.
    fn valid_codesigning_identities() -> Vec<String> {
        let output = Command::new("security")
            .args(["find-identity", "-v", "-p", "codesigning"])
            .output()
            .expect("spawn security find-identity");
        assert!(
            output.status.success(),
            "security find-identity failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8_lossy(&output.stdout)
            .lines()
            .filter_map(|line| {
                let (_, rest) = line.split_once('"')?;
                Some(rest.trim_end_matches('"').to_string())
            })
            .collect()
    }

    /// Production identity для подписи helper.
    ///
    /// Явный `RUNNE_MACOS_SIGNING_IDENTITY` fail-closed: значение обязано
    /// быть среди валидных identity keychain. Без переменной используется
    /// первый найденный Developer ID Application. `None` означает, что
    /// identity недоступна и caller обязан откатиться на ad-hoc test-signing.
    fn resolve_developer_id_identity() -> Option<String> {
        if let Some(requested) = std::env::var("RUNNE_MACOS_SIGNING_IDENTITY")
            .ok()
            .filter(|value| !value.trim().is_empty())
        {
            let identities = valid_codesigning_identities();
            assert!(
                identities.contains(&requested),
                "RUNNE_MACOS_SIGNING_IDENTITY={requested} not found among valid identities"
            );
            return Some(requested);
        }
        valid_codesigning_identities()
            .into_iter()
            .find(|id| id.contains("Developer ID Application:"))
    }

    /// Подписывает helper.
    ///
    /// Production Developer ID path добавляет hardened runtime и secure
    /// timestamp, зеркаля `scripts/sign-macos-binary.sh`. Ad-hoc `"-"`
    /// остаётся только fallback-ом для окружений без identity (CI/development).
    /// Entitlements не применяются: spike использует явный `sandbox_init`, а не
    /// app-sandbox entitlement.
    fn sign_helper(binary: &std::path::Path, identity: &str) {
        let mut command = Command::new("codesign");
        command.args(["--sign", identity, "--force"]);
        if identity != "-" {
            command.args(["--options", "runtime", "--timestamp"]);
        }
        let status = command.arg(binary).status().expect("spawn codesign");
        assert!(status.success(), "codesign failed");

        if identity != "-" {
            let status = Command::new("codesign")
                .args(["--verify", "--verbose"])
                .arg(binary)
                .status()
                .expect("spawn codesign --verify");
            assert!(
                status.success(),
                "codesign --verify failed for identity {identity}"
            );
        }
    }

    #[test]
    fn sandbox_api_probe_reports_availability() {
        if !seatbelt_available() {
            eprintln!("skipping: Seatbelt cannot be applied in this process tree");
            return;
        }
        assert!(
            probe_sandbox_api(),
            "sandbox API should be available when sandbox-exec succeeds"
        );
    }

    #[test]
    fn sandboxed_helper_denies_etc_passwd() {
        // Собираем и подписываем helper (Developer ID при доступности,
        // иначе ad-hoc), затем запускаем --self-test.
        build_helper();
        let identity = resolve_developer_id_identity();
        let identity = identity.as_deref().unwrap_or("-");
        sign_helper(&helper_binary_path(), identity);

        if !seatbelt_available() {
            eprintln!("skipping: Seatbelt cannot be applied in this process tree");
            return;
        }

        let status = Command::new(helper_binary_path())
            .arg("--self-test")
            .status()
            .expect("spawn helper");
        assert!(
            status.success(),
            "sandboxed helper self-test should deny /etc/passwd"
        );
    }

    /// Production-signing путь: helper, подписанный реальным Developer ID
    /// Application identity, проходит тот же sandbox self-test. На машинах без
    /// identity тест пропускается (graceful skip, как у Linux cgroups probe).
    #[test]
    fn developer_id_signed_helper_passes_self_test() {
        let Some(identity) = resolve_developer_id_identity() else {
            eprintln!("skipping: no Developer ID Application identity in keychain");
            return;
        };
        build_helper();

        // Подписываем приватную копию, чтобы не соревноваться с другими
        // тестами за общий target/debug binary.
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system time")
            .as_nanos();
        let copy = std::env::temp_dir().join(format!(
            "runne-sandbox-helper-dev-id-{unique}-{}",
            std::process::id()
        ));
        std::fs::copy(helper_binary_path(), &copy).expect("copy helper");

        struct RemoveOnDrop(std::path::PathBuf);
        impl Drop for RemoveOnDrop {
            fn drop(&mut self) {
                let _ = std::fs::remove_file(&self.0);
            }
        }
        let _cleanup = RemoveOnDrop(copy.clone());

        sign_helper(&copy, &identity);

        let status = Command::new(&copy)
            .arg("--self-test")
            .status()
            .expect("spawn helper");
        assert!(
            status.success(),
            "Developer ID signed helper self-test should deny /etc/passwd \
             (identity {identity})"
        );
    }
}
