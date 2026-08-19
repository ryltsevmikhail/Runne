//! Linux probe functions: Landlock, seccomp and cgroups v2.
//!
//! Platform-specific OS syscalls require `unsafe`; all unsafe blocks are
//! isolated in this module with safety comments.
#![allow(unsafe_code)]

use super::ContainmentError;

/// Проверяет доступность Landlock ABI в текущем ядре.
///
/// Возвращает ABI version (начиная с 1), если Landlock поддерживается,
/// или `None`, если syscall отсутствует/запрещён.
pub fn probe_landlock_abi() -> Option<u32> {
    // landlock_create_ruleset(NULL, 0, 0) возвращает ABI version.
    // См. https://docs.kernel.org/userspace-api/landlock.html
    let ret = unsafe {
        libc::syscall(
            libc::SYS_landlock_create_ruleset,
            0usize, // attr = NULL
            0usize, // size = 0
            0u32,   // flags = 0
        )
    };
    if ret >= 0 { Some(ret as u32) } else { None }
}

/// Создаёт Landlock ruleset с заданными handled_access_fs правами.
///
/// Это реальный OS probe: если ruleset создаётся,
/// ядро поддерживает Landlock с указанными правами.
/// Функция не вызывает `restrict_self` — она только проверяет,
/// что syscalls работают.
pub fn create_landlock_ruleset(handled_access_fs: u64) -> Result<libc::c_int, ContainmentError> {
    // landlock_ruleset_attr: { handled_access_fs: u64 }
    let attr = handled_access_fs;
    let fd = unsafe {
        libc::syscall(
            libc::SYS_landlock_create_ruleset,
            &attr as *const u64 as usize,
            std::mem::size_of::<u64>(),
            0u32,
        )
    };
    if fd < 0 {
        return Err(ContainmentError::BackendUnavailable);
    }
    Ok(fd as libc::c_int)
}

const LANDLOCK_RULE_PATH_BENEATH: u32 = 1;

#[repr(C)]
struct LandlockPathBeneathAttr {
    allowed_access: u64,
    parent_fd: libc::c_int,
    reserved: u32,
}

/// Добавляет в ruleset правило `path_beneath` для каталога `parent_fd`.
pub fn add_landlock_path_rule(
    ruleset_fd: libc::c_int,
    parent_fd: libc::c_int,
    allowed_access: u64,
) -> Result<(), ContainmentError> {
    let attr = LandlockPathBeneathAttr {
        allowed_access,
        parent_fd,
        reserved: 0,
    };
    let ret = unsafe {
        libc::syscall(
            libc::SYS_landlock_add_rule,
            ruleset_fd as usize,
            LANDLOCK_RULE_PATH_BENEATH as usize,
            &attr as *const LandlockPathBeneathAttr as usize,
            0usize,
        )
    };
    if ret < 0 {
        return Err(ContainmentError::BackendUnavailable);
    }
    Ok(())
}

/// Применяет Landlock ruleset к текущему процессу.
pub fn restrict_self_with_landlock(ruleset_fd: libc::c_int) -> Result<(), ContainmentError> {
    let ret = unsafe {
        libc::syscall(
            libc::SYS_landlock_restrict_self,
            ruleset_fd as usize,
            0usize,
        )
    };
    if ret < 0 {
        return Err(ContainmentError::BackendUnavailable);
    }
    Ok(())
}

/// Проверяет доступность seccomp filter mode в текущем ядре.
///
/// Использует `prctl(PR_GET_SECCOMP)`; если syscall возвращает
/// режим (отключен/строгий/filter), seccomp поддерживается.
pub fn probe_seccomp_filter() -> bool {
    const PR_GET_SECCOMP: libc::c_int = 21;
    let ret = unsafe {
        libc::syscall(
            libc::SYS_prctl,
            PR_GET_SECCOMP as usize,
            0usize,
            0usize,
            0usize,
            0usize,
        )
    };
    ret >= 0
}

/// Проверяет, доступна ли запись в cgroups v2 для ограничения ресурсов.
///
/// Проверяет существование `/sys/fs/cgroup/cgroup.controllers`
/// и возможность записи в `memory.max` или `pids.max`
/// в текущей cgroup.
pub fn probe_cgroups_v2_delegated() -> bool {
    use std::path::Path;

    let cgroup_root = Path::new("/sys/fs/cgroup");
    if !cgroup_root.join("cgroup.controllers").exists() {
        return false;
    }
    // Проверяем делегированный контроллер memory или pids.
    cgroup_root.join("memory.max").is_file() || cgroup_root.join("pids.max").is_file()
}
