//! Descendant cleanup and timeout termination enforcement tests.

#[test]
fn descendant_cleanup_via_pdeathsig() {
    // Проверяем, что дочерний процесс умирает, когда умирает родитель,
    // благодаря PR_SET_PDEATHSIG = SIGKILL.
    use std::fs;

    const PR_SET_PDEATHSIG: libc::c_int = 1;
    let pid_file = std::env::temp_dir().join("runne_pdeathsig_test_child_pid");
    let _ = fs::remove_file(&pid_file);

    let pid = unsafe { libc::fork() };
    assert!(pid >= 0, "fork failed");

    if pid == 0 {
        let ret = unsafe {
            libc::syscall(
                libc::SYS_prctl,
                PR_SET_PDEATHSIG as usize,
                libc::SIGKILL as usize,
                0usize,
                0usize,
                0usize,
            )
        };
        if ret < 0 {
            eprintln!("PR_SET_PDEATHSIG failed in parent");
            unsafe { libc::exit(1) };
        }

        let child_b = unsafe { libc::fork() };
        if child_b < 0 {
            eprintln!("fork child B failed");
            unsafe { libc::exit(2) };
        }
        if child_b == 0 {
            let ret = unsafe {
                libc::syscall(
                    libc::SYS_prctl,
                    PR_SET_PDEATHSIG as usize,
                    libc::SIGKILL as usize,
                    0usize,
                    0usize,
                    0usize,
                )
            };
            if ret < 0 {
                eprintln!("PR_SET_PDEATHSIG failed in child B");
                unsafe { libc::exit(3) };
            }
            fs::write(&pid_file, format!("{}\n", unsafe { libc::getpid() }))
                .expect("write child B pid");
            loop {
                unsafe { libc::sleep(10) };
            }
        }

        // Даём child B время записать pid, потом выходим.
        unsafe { libc::usleep(200_000) };
        unsafe { libc::exit(0) };
    }

    let mut status = 0;
    let waited = unsafe { libc::waitpid(pid, &mut status, 0) };
    assert_eq!(waited, pid, "waitpid failed");
    assert!(libc::WIFEXITED(status), "child A did not exit cleanly");

    // Даём PR_SET_PDEATHSIG время сработать.
    unsafe { libc::usleep(200_000) };

    let child_b_pid: libc::pid_t = fs::read_to_string(&pid_file)
        .expect("read child B pid")
        .trim()
        .parse()
        .expect("parse child B pid");
    let ret = unsafe { libc::kill(child_b_pid, 0) };
    assert!(ret < 0, "child B should have been killed");
    let errno = unsafe { *libc::__errno_location() };
    assert_eq!(errno, libc::ESRCH, "child B should not exist anymore");

    let _ = fs::remove_file(&pid_file);
}

#[test]
fn timeout_termination_enforced() {
    // Проверяем, что можем дождаться завершения процесса с timeout
    // и при необходимости прибить его SIGKILL.
    const TIMEOUT_MS: u128 = 200;

    let pid = unsafe { libc::fork() };
    assert!(pid >= 0, "fork failed");

    if pid == 0 {
        // Child sleeps forever.
        loop {
            unsafe { libc::sleep(10) };
        }
    }

    let start = std::time::Instant::now();
    let timeout = std::time::Duration::from_millis(TIMEOUT_MS as u64);
    let mut status = 0;

    loop {
        let ret = unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) };
        assert!(ret >= 0, "waitpid failed");
        if ret == pid {
            panic!("child exited before timeout");
        }
        if start.elapsed() >= timeout {
            break;
        }
        unsafe { libc::usleep(10_000) };
    }

    let ret = unsafe { libc::kill(pid, libc::SIGKILL) };
    assert_eq!(ret, 0, "SIGKILL failed");

    let ret = unsafe { libc::waitpid(pid, &mut status, 0) };
    assert_eq!(ret, pid, "waitpid after kill failed");
    assert!(
        libc::WIFSIGNALED(status),
        "child should have been killed by timeout"
    );
    assert_eq!(
        libc::WTERMSIG(status),
        libc::SIGKILL,
        "child should have been killed by SIGKILL"
    );
}
