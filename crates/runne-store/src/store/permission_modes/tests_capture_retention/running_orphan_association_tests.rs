//! Pure parser vectors only; no proc/namespace/native operation.
use super::*;
fn rejects(f: impl FnOnce() + std::panic::UnwindSafe) {
    assert!(std::panic::catch_unwind(f).is_err());
}
fn stat(comm: &str, state: &str, parent: &str, start: &str) -> String {
    let mut tail = vec!["0"; 20];
    tail[0] = state;
    tail[1] = parent;
    tail[19] = start;
    format!("47 ({comm}) {}\n", tail.join(" "))
}
#[test]
fn exact_stat_preserves_start_ticks_and_handles_comm_parentheses() {
    for comm in ["sh", "a b", "a) b", "a (b) c"] {
        assert_eq!(stat_identity(&stat(comm, "S", "41", "1234"), 47, 41), 1234);
    }
}
#[test]
fn stat_refuses_wrong_pid_parent_dead_state_and_bad_start() {
    let good = stat("sh", "S", "41", "1234");
    rejects(|| {
        stat_identity(&good, 48, 41);
    });
    rejects(|| {
        stat_identity(&good, 47, 42);
    });
    for state in ["Z", "X", "x", "unknown"] {
        rejects(|| {
            stat_identity(&stat("sh", state, "41", "1234"), 47, 41);
        });
    }
    for start in ["0", "+1", "-1", "01", "18446744073709551616"] {
        rejects(|| {
            stat_identity(&stat("sh", "S", "41", start), 47, 41);
        });
    }
    rejects(|| {
        stat_identity("47 (sh) S 41\n", 47, 41);
    });
}
#[test]
fn exact_status_uses_parent_outer_pid_and_initial_inner_leader() {
    let text = "Name:\tsh\nTgid:\t47\nPid:\t47\nPPid:\t41\nNSpid:\t47\t1\n";
    assert_eq!(status_pids(text, 47, 41), [47, 1]);
    for (from, to) in [
        ("Pid:\t47", "Pid:\t48"),
        ("PPid:\t41", "PPid:\t42"),
        ("NSpid:\t47\t1", "NSpid:\t47\t2"),
        ("NSpid:\t47\t1", "NSpid:\t47"),
        ("NSpid:\t47\t1", "NSpid:\t47\t9\t1"),
    ] {
        rejects(|| {
            status_pids(&text.replace(from, to), 47, 41);
        });
    }
    rejects(|| {
        status_pids(&format!("{text}Pid:\t47\n"), 47, 41);
    });
    rejects(|| {
        status_pids(&text.replace("NSpid:\t47\t1\n", ""), 47, 41);
    });
}
#[test]
fn positive_decimal_limits_are_checked_without_signs_or_overflow() {
    assert_eq!(number("18446744073709551615"), u64::MAX);
    assert_eq!(pid("2147483647"), i32::MAX as u32);
    for value in ["", "0", "01", "+2", "-2", "18446744073709551616"] {
        rejects(|| {
            number(value);
        });
    }
    for value in ["1", "2147483648"] {
        rejects(|| {
            pid(value);
        });
    }
}
#[test]
fn membership_is_a_single_safe_absolute_unified_path() {
    assert_eq!(membership("0::/runne/root\n"), "/runne/root");
    assert_eq!(membership("0::/\n"), "/");
    for value in [
        "",
        "1:cpu:/x\n",
        "0::relative\n",
        "0::/x\n0::/y\n",
        "0::/../x\n",
        "0::/./x\n",
        "0::/x\\040y\n",
        "0::/x\ty\n",
        "0::/x\0y\n",
    ] {
        rejects(|| {
            membership(value);
        });
    }
}
