use super::super::LinuxCommandError;
use runne_application::permission_modes::IntegrityDigest;
use runne_application::permission_modes::NetworkScope;
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

pub(super) fn digest_v2(
    roots: &[&File],
    network: NetworkScope,
) -> Result<IntegrityDigest, LinuxCommandError> {
    let strategy = match network {
        NetworkScope::BroadSameUser => b"broad-ip-network-v2\0".as_slice(),
        NetworkScope::None => b"network-none-v2\0".as_slice(),
        _ => return Err(LinuxCommandError::CompositePolicyUnenforceable),
    };
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
    hash.update(b"runne:d21:linux-protected-control-plane:v2\0");
    hash.update(b"userns+mountns+pidns;proc-subset-pid;sys-hidden;safe-devices;close-protected-fds;regular-nlink-one;deny-af-unix;");
    hash.update(strategy);
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

pub(super) fn digest_v3(
    roots: &[&File],
    network: NetworkScope,
) -> Result<IntegrityDigest, LinuxCommandError> {
    let network_profile = match network {
        NetworkScope::BroadSameUser => b"broad-ip-network-v3\0".as_slice(),
        NetworkScope::None => b"network-none-v3\0".as_slice(),
        _ => return Err(LinuxCommandError::CompositePolicyUnenforceable),
    };
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
    hash.update(b"runne:d21:linux-protected-control-plane:v3\0");
    hash.update(b"userns+mountns+pidns;proc-subset-pid;sys-hidden;safe-devices;close-protected-fds;regular-nlink-one;deny-af-unix;fs-rights-mapping-v1;landlock-abi>=3;seccomp-write-metadata-v1;seccomp-rename-v1;");
    hash.update(network_profile);
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

impl super::PreparedComposite {
    pub(in crate::local_command_linux) fn protected_policy_digest_v2(
        roots: &[&File],
        network: NetworkScope,
    ) -> Result<IntegrityDigest, LinuxCommandError> {
        super::validate_host_shape(roots)?;
        digest_v2(roots, network)
    }

    pub(in crate::local_command_linux) fn protected_policy_digest_v3(
        roots: &[&File],
        network: NetworkScope,
    ) -> Result<IntegrityDigest, LinuxCommandError> {
        super::validate_host_shape(roots)?;
        digest_v3(roots, network)
    }
}
