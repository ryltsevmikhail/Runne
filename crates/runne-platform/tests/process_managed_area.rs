#![cfg(target_os = "linux")]

use runne_platform::process_managed_area::{
    LinuxManagedAreaRoot, ManagedAreaBinding, ManagedAreaError, ManagedAreaIdentity,
};
use rustix::process::{Pid, PidfdFlags, Signal, pidfd_open, pidfd_send_signal};
use std::io::{BufRead, BufReader};
use std::ops::{Deref, DerefMut};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

#[path = "process_managed_area/proof.rs"]
mod proof;
#[path = "process_managed_area/terminal_cleanup.rs"]
mod terminal_cleanup;

fn binding(nonce: u8) -> ManagedAreaBinding {
    let tick = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    let mut token = [0; 16];
    token[..4].copy_from_slice(&std::process::id().to_be_bytes());
    token[4..12].copy_from_slice(&tick.to_be_bytes()[8..]);
    token[15] = nonce;
    ManagedAreaBinding::new([11; 16], [12; 16], token).expect("valid binding")
}

fn root_or_skip() -> Option<LinuxManagedAreaRoot> {
    match LinuxManagedAreaRoot::open_current_cgroup() {
        Ok(root) => Some(root),
        Err(_) => {
            eprintln!("SKIP: private delegated cgroup scope unavailable");
            None
        }
    }
}

fn area_or_skip(root: &LinuxManagedAreaRoot, bind: ManagedAreaBinding) -> Option<TestArea> {
    match root.create_area(bind) {
        Ok(area) => Some(TestArea(Some(area))),
        Err(ManagedAreaError::Unavailable) => {
            eprintln!("SKIP: private cgroup child creation unavailable");
            None
        }
        Err(error) => panic!("unexpected area creation failure: {error}"),
    }
}

struct TestArea(Option<runne_platform::process_managed_area::LinuxManagedArea>);
impl TestArea {
    fn take(mut self) -> runne_platform::process_managed_area::LinuxManagedArea {
        self.0.take().expect("area")
    }
    fn remove_empty(self) {
        self.take().remove_empty().expect("remove empty area");
    }
}
impl Deref for TestArea {
    type Target = runne_platform::process_managed_area::LinuxManagedArea;
    fn deref(&self) -> &Self::Target {
        self.0.as_ref().expect("area")
    }
}
impl DerefMut for TestArea {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.0.as_mut().expect("area")
    }
}
impl Drop for TestArea {
    fn drop(&mut self) {
        if let Some(area) = self.0.take() {
            let _ = area.terminate(Duration::ZERO);
            let _ = area.remove_empty();
        }
    }
}

struct TestChild(Child);
impl Deref for TestChild {
    type Target = Child;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
impl DerefMut for TestChild {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}
impl Drop for TestChild {
    fn drop(&mut self) {
        if self.0.try_wait().ok().flatten().is_none()
            && let Some(pid) = Pid::from_raw(self.0.id() as i32)
            && let Ok(fd) = pidfd_open(pid, PidfdFlags::empty())
        {
            let _ = pidfd_send_signal(&fd, Signal::KILL);
        }
        let _ = self.0.wait();
    }
}

#[test]
fn identity_roundtrips_and_live_area_rejects_each_binding_field_tamper() {
    let Some(root) = root_or_skip() else { return };
    let bind = binding(21);
    let Some(area) = area_or_skip(&root, bind) else {
        return;
    };
    eprintln!("RUN: identity_roundtrips_and_live_area_rejects_each_binding_field_tamper");
    let bytes = area.identity().to_bytes();
    let identity = ManagedAreaIdentity::from_bytes(&bytes).expect("decode");
    assert_eq!(identity.to_bytes(), bytes);
    assert_eq!(
        root.reopen_area(identity.clone(), binding(22)).err(),
        Some(ManagedAreaError::Unverified)
    );
    for offset in [4usize, 20, 28, 36, 44] {
        let mut changed = bytes;
        changed[offset] ^= 1;
        let changed =
            ManagedAreaIdentity::from_bytes(&changed).expect("syntactically valid tamper");
        assert_eq!(
            root.reopen_area(changed, bind).err(),
            Some(ManagedAreaError::Unverified),
            "offset {offset}"
        );
    }
    assert_eq!(
        ManagedAreaIdentity::from_bytes(&bytes[..99]).err(),
        Some(ManagedAreaError::InvalidIdentity)
    );
    let reopened = root
        .reopen_area(identity, bind)
        .expect("positive exact reopen while live");
    reopened.remove_empty().expect("remove empty area");
}

#[test]
fn replaced_area_rejects_old_identity_and_accepts_new_identity() {
    let Some(root) = root_or_skip() else { return };
    let bind = binding(41);
    let Some(area) = area_or_skip(&root, bind) else {
        return;
    };
    eprintln!("RUN: replaced_area_rejects_old_identity_and_accepts_new_identity");
    let old = area.identity().clone();
    area.remove_empty();
    let replacement = root
        .create_area(bind)
        .expect("same binding/name can be recreated");
    assert_ne!(
        replacement.identity().to_bytes(),
        old.to_bytes(),
        "replacement has a new exact identity"
    );
    assert_eq!(
        root.reopen_area(old, bind).err(),
        Some(ManagedAreaError::Unverified)
    );
    let current = root
        .reopen_area(replacement.identity().clone(), bind)
        .expect("new exact identity reopens");
    current.remove_empty().expect("remove replacement");
}

#[test]
fn terminate_finds_detached_term_ignoring_grandchild_after_leader_exit() {
    let Some(root) = root_or_skip() else { return };
    let bind = binding(31);
    let Some(area) = area_or_skip(&root, bind) else {
        return;
    };
    eprintln!("RUN: terminate_finds_detached_term_ignoring_grandchild_after_leader_exit");
    let mut leader = match Command::new("sh").args(["-c", r#"kill -STOP $$; setsid sh -c 'trap "" TERM; printf "ready:%s\n" "$$"; while :; do sleep 1; done' & exit 0"#])
        .stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::null()).spawn() {
        Ok(child) => TestChild(child),
        Err(_) => { eprintln!("SKIP: shell fixture unavailable"); area.remove_empty(); return; }
    };
    wait_stopped(&leader);
    area.attach_gated_process(leader.id())
        .expect("attach caller-owned stopped child");
    send_signal(leader.id(), Signal::CONT);
    let stdout = leader.stdout.take().expect("fixture stdout");
    let mut reader = BufReader::new(stdout);
    let mut pid_line = String::new();
    reader.read_line(&mut pid_line).expect("read detached pid");
    let detached_pid = pid_line
        .strip_prefix("ready:")
        .expect("TERM-ignore trap installed before readiness")
        .trim()
        .parse::<u32>()
        .expect("detached pid number");
    wait_child(&mut leader);
    assert_eq!(
        process_session(detached_pid),
        Some(detached_pid),
        "grandchild established independent session"
    );
    assert!(
        area.is_populated().expect("population evidence"),
        "descendant remains after leader is reaped"
    );
    assert_process_alive(detached_pid);
    area.terminate(Duration::from_millis(150))
        .expect("exact-area kill and recursive empty proof");
    wait_process_dead(detached_pid);
    area.remove_empty();
}

fn wait_stopped(child: &Child) {
    let started = Instant::now();
    loop {
        if std::fs::read_to_string(format!("/proc/{}/status", child.id()))
            .ok()
            .is_some_and(|text| {
                text.lines()
                    .any(|line| line.starts_with("State:") && line.contains('T'))
            })
        {
            return;
        }
        assert!(
            started.elapsed() < Duration::from_secs(3),
            "fixture did not reach gate"
        );
        thread::sleep(Duration::from_millis(5));
    }
}
fn process_session(pid: u32) -> Option<u32> {
    let text = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    text.rsplit_once(')')?
        .1
        .split_whitespace()
        .nth(3)?
        .parse()
        .ok()
}
fn assert_process_alive(pid: u32) {
    assert!(
        std::fs::read_to_string(format!("/proc/{pid}/stat")).is_ok(),
        "detached descendant is alive before cleanup"
    );
}
fn wait_process_dead(pid: u32) {
    let started = Instant::now();
    loop {
        let state = std::fs::read_to_string(format!("/proc/{pid}/stat"))
            .ok()
            .and_then(|text| {
                text.rsplit_once(')')
                    .map(|(_, tail)| tail.split_whitespace().next().unwrap_or("").to_owned())
            });
        if state.is_none() || state.as_deref() == Some("Z") {
            return;
        }
        assert!(
            started.elapsed() < Duration::from_secs(3),
            "detached process remains alive"
        );
        thread::sleep(Duration::from_millis(5));
    }
}
fn send_signal(pid: u32, signal: Signal) {
    let pidfd =
        pidfd_open(Pid::from_raw(pid as i32).expect("pid"), PidfdFlags::empty()).expect("pidfd");
    pidfd_send_signal(&pidfd, signal).expect("signal held child identity");
}
fn wait_child(child: &mut Child) {
    let started = Instant::now();
    loop {
        if child.try_wait().expect("wait").is_some() {
            return;
        }
        assert!(
            started.elapsed() < Duration::from_secs(3),
            "leader did not exit"
        );
        thread::sleep(Duration::from_millis(5));
    }
}
