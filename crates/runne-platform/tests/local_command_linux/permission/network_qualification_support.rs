use super::network_none::support as none;
use runne_application::permission_modes::{EffectBudget, NetworkScope, admit_invocation_scope};
use runne_platform::local_command_linux::GatedLinuxChild;
use std::ffi::c_void;
use std::time::{Duration, Instant};

pub(super) fn fixture(network: NetworkScope) -> none::Fixture {
    let mut fixture = none::fixture().expect("delegated cgroup-v2 scope is required");
    if network != NetworkScope::None {
        fixture.scope = none::closed_scope(
            &fixture.admission,
            network,
            EffectBudget {
                max_operations: None,
                max_bytes: None,
            },
        );
        fixture.receipt = admit_invocation_scope(&fixture.scope, &fixture.admission)
            .expect("fresh receipt for requested network scope");
    }
    assert_eq!(fixture.scope.network, network);
    fixture
}

pub(super) fn finish_child(
    mut child: GatedLinuxChild<'_>,
    timeout: Duration,
) -> (i32, Vec<u8>, Vec<u8>) {
    let deadline = Instant::now() + timeout;
    let mut status = None;
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    loop {
        child.poll_output().expect("bounded child output");
        let chunk = child.take_output();
        assert!(!chunk.stdout_truncated && !chunk.stderr_truncated);
        stdout.extend_from_slice(&chunk.stdout);
        stderr.extend_from_slice(&chunk.stderr);
        if status.is_none() {
            status = child.try_wait().expect("reap direct child");
        }
        if chunk.stdout_eof
            && chunk.stderr_eof
            && let Some(code) = status
        {
            return (code, stdout, stderr);
        }
        if Instant::now() >= deadline {
            let cleanup = child.cancel(Duration::from_millis(20));
            panic!("child exceeded {timeout:?}; bounded cancellation: {cleanup:?}");
        }
        std::thread::sleep(Duration::from_millis(5));
    }
}

#[derive(Clone, Copy)]
pub(super) struct Probe {
    pub(super) name: &'static str,
    pub(super) number: libc::c_long,
    pub(super) kind: Kind,
}

#[derive(Clone, Copy)]
pub(super) enum Kind {
    Recvfrom,
    Message,
    MultiMessage,
    MultiMessageTimed,
    Accept4,
    Name,
    Shutdown,
    SetOption,
    GetOption,
    UringSetup,
    UringEnter,
    UringRegister,
}

#[repr(C, align(16))]
pub(super) struct Aligned(pub(super) [u8; 512]);

pub(super) fn socket_baseline(number: libc::c_long, family: i32, kind: i32) -> (libc::c_long, i32) {
    unsafe { *libc::__errno_location() = 0 };
    let result = unsafe { libc::syscall(number, family, kind, 0) };
    let errno = errno_for(result);
    if result >= 0 {
        unsafe { libc::close(result as libc::c_int) };
    }
    (result, errno)
}

pub(super) fn parent_baseline(
    probe: Probe,
    memory: &mut Aligned,
    option: &mut i32,
    option_len: &mut libc::socklen_t,
    address_len: &mut u32,
) -> (libc::c_long, i32) {
    unsafe { *libc::__errno_location() = 0 };
    let pointer = memory.0.as_mut_ptr().cast::<c_void>();
    *option_len = std::mem::size_of::<i32>() as libc::socklen_t;
    *address_len = 128;
    let result = unsafe {
        match probe.kind {
            Kind::Recvfrom => libc::syscall(
                probe.number,
                -1_i32,
                pointer,
                1_usize,
                0_i32,
                pointer,
                address_len as *mut u32,
            ),
            Kind::Message => libc::syscall(probe.number, -1_i32, pointer, 0_i32),
            Kind::MultiMessage => libc::syscall(probe.number, -1_i32, pointer, 1_u32, 0_u32),
            Kind::MultiMessageTimed => libc::syscall(
                probe.number,
                -1_i32,
                pointer,
                1_u32,
                0_u32,
                std::ptr::null_mut::<libc::timespec>(),
            ),
            Kind::Accept4 => libc::syscall(
                probe.number,
                -1_i32,
                pointer,
                address_len as *mut u32,
                0_i32,
            ),
            Kind::Name => libc::syscall(probe.number, -1_i32, pointer, address_len as *mut u32),
            Kind::Shutdown => libc::syscall(probe.number, -1_i32, libc::SHUT_RDWR),
            Kind::SetOption => libc::syscall(
                probe.number,
                -1_i32,
                libc::SOL_SOCKET,
                libc::SO_RCVBUF,
                option as *mut i32,
                std::mem::size_of::<i32>() as libc::socklen_t,
            ),
            Kind::GetOption => libc::syscall(
                probe.number,
                -1_i32,
                libc::SOL_SOCKET,
                libc::SO_RCVBUF,
                option as *mut i32,
                option_len as *mut libc::socklen_t,
            ),
            Kind::UringSetup => libc::syscall(probe.number, 1_u32, pointer),
            Kind::UringEnter => libc::syscall(
                probe.number,
                -1_i32,
                0_u32,
                0_u32,
                0_u32,
                std::ptr::null::<c_void>(),
                0_usize,
            ),
            Kind::UringRegister => {
                let mut target = [0_u8; 8];
                let mut iovec = libc::iovec {
                    iov_base: target.as_mut_ptr().cast(),
                    iov_len: target.len(),
                };
                libc::syscall(
                    probe.number,
                    i32::MAX,
                    0_u32,
                    &mut iovec as *mut libc::iovec,
                    1_u32,
                )
            }
        }
    };
    (result, errno_for(result))
}

fn errno_for(result: libc::c_long) -> i32 {
    if result == -1 {
        std::io::Error::last_os_error().raw_os_error().unwrap_or(-1)
    } else {
        0
    }
}
