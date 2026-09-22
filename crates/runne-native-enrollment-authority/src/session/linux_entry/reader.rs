//! Resolve only the live daemon authenticated by the inherited control socket.
use runne_provider::{
    CredentialWriterSessionAttestationCodec, CredentialWriterSessionAttestationV2Codec,
};
use sha2::{Digest as _, Sha256};
use std::{os::unix::net::UnixStream, path::PathBuf};

struct Peer {
    pid: u32,
    start: [u8; 32],
    image: [u8; 32],
    path: PathBuf,
}

pub(super) fn verified_reader_path(
    control: &UnixStream,
    bytes: &[u8],
    key: [u8; 32],
    writer_start: [u8; 32],
    writer_image: [u8; 32],
) -> Result<PathBuf, &'static str> {
    let peer = capture(control)?;
    let matches = match bytes.first() {
        Some(1) => CredentialWriterSessionAttestationCodec::decode_and_verify(bytes, key)
            .map_err(|_| "reader attestation denied")?
            .matches_live_processes(&writer_start, &writer_image, &peer.start, &peer.image),
        Some(2) => CredentialWriterSessionAttestationV2Codec::decode_and_verify(bytes, key)
            .map_err(|_| "reader attestation denied")?
            .matches_live_processes(&writer_start, &writer_image, &peer.start, &peer.image),
        _ => return Err("reader attestation version denied"),
    };
    let confirmed = capture(control)?;
    if !matches
        || confirmed.pid != peer.pid
        || confirmed.start != peer.start
        || confirmed.image != peer.image
        || confirmed.path != peer.path
    {
        return Err("live reader identity mismatch");
    }
    Ok(peer.path)
}

fn capture(control: &UnixStream) -> Result<Peer, &'static str> {
    let credential =
        rustix::net::sockopt::socket_peercred(control).map_err(|_| "reader peer unavailable")?;
    let pid = u32::try_from(credential.pid.as_raw_pid()).map_err(|_| "reader pid denied")?;
    if pid == 0 || pid == std::process::id() || credential.uid != rustix::process::geteuid() {
        return Err("reader peer denied");
    }
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat"))
        .map_err(|_| "reader start unavailable")?;
    let ticks = stat
        .rsplit_once(')')
        .and_then(|(_, tail)| tail.split_whitespace().nth(19))
        .ok_or("reader start denied")?;
    let mut start = Sha256::new();
    start.update(b"gocode.provider-credential-writer.start.v1");
    start.update(pid.to_be_bytes());
    start.update(ticks.as_bytes());
    let executable = PathBuf::from(format!("/proc/{pid}/exe"));
    let path = std::fs::canonicalize(&executable).map_err(|_| "reader image unavailable")?;
    let image = hash(&executable)?;
    if hash(&path)? != image {
        return Err("reader installed image mismatch");
    }
    Ok(Peer {
        pid,
        start: start.finalize().into(),
        image,
        path,
    })
}

fn hash(path: &std::path::Path) -> Result<[u8; 32], &'static str> {
    std::fs::read(path)
        .map(|bytes| Sha256::digest(bytes).into())
        .map_err(|_| "reader image unavailable")
}
