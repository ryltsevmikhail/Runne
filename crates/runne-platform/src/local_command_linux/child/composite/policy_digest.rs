use super::super::LinuxCommandError;
use runne_application::permission_modes::IntegrityDigest;
use rustix::fs::fstat;
use sha2::{Digest, Sha256};
use std::fs::File;

pub(super) fn digest(roots: &[&File]) -> Result<IntegrityDigest, LinuxCommandError> {
    let mut identities = roots
        .iter()
        .map(|root| {
            let stat = fstat(*root).map_err(|_| LinuxCommandError::CompositePolicyUnenforceable)?;
            Ok((
                stat.st_dev,
                stat.st_ino,
                stat.st_mode,
                stat.st_uid,
                stat.st_gid,
            ))
        })
        .collect::<Result<Vec<_>, LinuxCommandError>>()?;
    identities.sort_unstable();
    let mut hash = Sha256::new();
    hash.update(b"runne:d21:linux-protected-control-plane:v1\0");
    hash.update(b"userns+mountns+pidns;proc-subset-pid;sys-hidden;safe-devices;close-protected-fds;regular-nlink-one;deny-af-unix;host-ip-network\0");
    hash.update((identities.len() as u32).to_be_bytes());
    for (device, inode, mode, uid, gid) in identities {
        hash.update(device.to_be_bytes());
        hash.update(inode.to_be_bytes());
        hash.update(mode.to_be_bytes());
        hash.update(uid.to_be_bytes());
        hash.update(gid.to_be_bytes());
    }
    Ok(IntegrityDigest::from_bytes(hash.finalize().into()))
}
