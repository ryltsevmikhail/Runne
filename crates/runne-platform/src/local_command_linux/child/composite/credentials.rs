//! Irreversible credential hardening inside the new user namespace.

pub(super) unsafe fn lock_securebits() -> i32 {
    const SECBIT_NOROOT_LOCKED: libc::c_int = 0x01 | 0x02;
    const SECBIT_NO_SETUID_FIXUP_LOCKED: libc::c_int = 0x04 | 0x08;
    unsafe {
        libc::prctl(
            libc::PR_SET_SECUREBITS,
            SECBIT_NOROOT_LOCKED | SECBIT_NO_SETUID_FIXUP_LOCKED,
            0,
            0,
            0,
        )
    }
}

pub(super) unsafe fn drop_capabilities() -> i32 {
    #[repr(C)]
    struct Header {
        version: u32,
        pid: i32,
    }
    #[repr(C)]
    #[derive(Clone, Copy)]
    struct Data {
        effective: u32,
        permitted: u32,
        inheritable: u32,
    }
    let header = Header {
        version: 0x2008_0522,
        pid: 0,
    };
    let data = [Data {
        effective: 0,
        permitted: 0,
        inheritable: 0,
    }; 2];
    unsafe { libc::syscall(libc::SYS_capset, &header, data.as_ptr()) as i32 }
}
