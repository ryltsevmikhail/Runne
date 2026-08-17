//! cgroups v2 pids.max enforcement test.

#[test]
fn cgroups_v2_pids_limit_enforced() {
    // Создаём дочернюю cgroup, ограничиваем pids.max = 2, перемещаем туда
    // forked child и проверяем, что второй fork() в ней завершается ошибкой
    // EAGAIN. Если cgroups v2 недоступен или смонтирован только для чтения
    // (как в Docker-контейнерах), тест пропускается.
    use std::fs;
    use std::path::PathBuf;

    let cgroup_root = PathBuf::from("/sys/fs/cgroup");
    if !cgroup_root.join("cgroup.controllers").exists() {
        eprintln!("skipping: cgroups v2 not available");
        return;
    }

    let child_cgroup = cgroup_root.join(format!("gocode_cgroup_pids_test_{}", unsafe {
        libc::getpid()
    }));
    let _ = fs::remove_dir(&child_cgroup);
    if fs::create_dir(&child_cgroup).is_err() {
        eprintln!("skipping: cannot create child cgroup (read-only cgroupfs?)");
        return;
    }

    // Включаем pids controller в родительской cgroup (может быть запрещено).
    let _ = fs::write(cgroup_root.join("cgroup.subtree_control"), "+pids\n");

    // Ограничиваем дочернюю cgroup двумя процессами.
    if fs::write(child_cgroup.join("pids.max"), "2\n").is_err() {
        let _ = fs::remove_dir(&child_cgroup);
        eprintln!("skipping: cannot write pids.max (read-only cgroupfs?)");
        return;
    }

    let pid = unsafe { libc::fork() };
    assert!(pid >= 0, "fork failed");

    if pid == 0 {
        // Child moves itself into the child cgroup.
        let self_pid = unsafe { libc::getpid() };
        if fs::write(child_cgroup.join("cgroup.procs"), format!("{}\n", self_pid)).is_err() {
            eprintln!("cannot move self to child cgroup");
            unsafe { libc::exit(4) };
        }

        // First fork succeeds: child + grandchild = 2 pids.
        let grandchild = unsafe { libc::fork() };
        if grandchild < 0 {
            eprintln!("first fork failed unexpectedly");
            unsafe { libc::exit(1) };
        }
        if grandchild == 0 {
            // Grandchild exits immediately.
            unsafe { libc::exit(0) };
        }
        let mut gc_status = 0;
        unsafe { libc::waitpid(grandchild, &mut gc_status, 0) };

        // Second fork must fail with EAGAIN because pids.max = 2.
        let second = unsafe { libc::fork() };
        if second == 0 {
            // If second fork succeeded, the limit was not enforced.
            unsafe { libc::exit(10) };
        }
        if second > 0 {
            // We succeeded in forking a second time: enforcement failed.
            let mut s = 0;
            unsafe { libc::waitpid(second, &mut s, 0) };
            eprintln!("second fork succeeded, pids.max not enforced");
            unsafe { libc::exit(2) };
        }
        let errno = unsafe { *libc::__errno_location() };
        if errno != libc::EAGAIN {
            eprintln!("second fork failed with unexpected errno {errno}");
            unsafe { libc::exit(3) };
        }

        unsafe { libc::exit(0) };
    }

    let mut status = 0;
    let waited = unsafe { libc::waitpid(pid, &mut status, 0) };
    assert_eq!(waited, pid, "waitpid failed");
    assert!(libc::WIFEXITED(status), "child did not exit cleanly");
    assert_eq!(
        libc::WEXITSTATUS(status),
        0,
        "child failed to verify cgroups pids.max enforcement"
    );

    let _ = fs::remove_dir(&child_cgroup);
}
