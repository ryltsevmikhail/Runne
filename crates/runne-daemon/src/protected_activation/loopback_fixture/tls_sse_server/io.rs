use super::*;
use tokio::io::AsyncReadExt as _;
pub(super) async fn read_request<S>(
    stream: &mut S,
    request_kind: FixtureRequestKind,
) -> Result<Vec<u8>, ()>
where
    S: tokio::io::AsyncRead + Unpin,
{
    const MAX_REQUEST_BYTES: usize = 512 * 1024;
    let mut request = Vec::new();
    let mut chunk = [0_u8; 4096];
    let headers_end = loop {
        let read = stream.read(&mut chunk).await.map_err(|_| ())?;
        if read == 0 || request.len().saturating_add(read) > MAX_REQUEST_BYTES {
            return Err(());
        }
        request.extend_from_slice(&chunk[..read]);
        if let Some(end) = request.windows(4).position(|window| window == b"\r\n\r\n") {
            break end + 4;
        }
    };
    let request_length = headers_end
        .checked_add(request_length_for(&request[..headers_end], request_kind)?)
        .ok_or(())?;
    if request_length > MAX_REQUEST_BYTES || request.len() > request_length {
        return Err(());
    }
    while request.len() < request_length {
        let read = stream.read(&mut chunk).await.map_err(|_| ())?;
        if read == 0 || request.len().saturating_add(read) > request_length {
            return Err(());
        }
        request.extend_from_slice(&chunk[..read]);
    }
    Ok(request)
}

pub(super) fn increment_request_count(path: &Path) -> Result<(), ()> {
    increment_named_count(path, "fixture-provider-request-count")
}

pub(super) fn increment_named_count(path: &Path, name: &str) -> Result<(), ()> {
    let path = path.parent().ok_or(())?.join(name);
    let count = match std::fs::read_to_string(&path) {
        Ok(value) => value.trim().parse::<u64>().map_err(|_| ())?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => 0,
        Err(_) => return Err(()),
    }
    .checked_add(1)
    .ok_or(())?;
    let temporary = temporary_path(&path);
    let result = (|| {
        let mut file = std::fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&temporary)
            .map_err(|_| ())?;
        use std::io::Write as _;
        file.write_all(count.to_string().as_bytes())
            .map_err(|_| ())?;
        file.sync_all().map_err(|_| ())?;
        drop(file);
        std::fs::rename(&temporary, &path).map_err(|_| ())
    })();
    if temporary.exists() {
        let _ = std::fs::remove_file(&temporary);
    }
    result
}

fn temporary_path(path: &Path) -> PathBuf {
    path.with_extension(format!("{}.tmp", uuid::Uuid::now_v7()))
}

/// D1.6 kill-matrix handshake inside the loopback fixture: mirrors the store
/// boundary gate (marker write, bounded release wait) so a test can SIGKILL
/// the daemon while the provider request is in flight or between stream
/// events. Test-support-only module.
pub(super) async fn hold_for_kill_boundary(boundary: &str) {
    use std::time::{Duration, Instant};
    let Ok(target) = std::env::var("RUNNE_TEST_KILL_BOUNDARY") else {
        return;
    };
    if target != boundary {
        return;
    }
    let Some(arm_file) = std::env::var_os("RUNNE_TEST_KILL_BOUNDARY_ARM") else {
        return;
    };
    if !std::path::Path::new(&arm_file).exists() {
        return;
    }
    let Some(marker) = std::env::var_os("RUNNE_TEST_KILL_BOUNDARY_MARKER") else {
        return;
    };
    let _ = tokio::fs::write(&marker, boundary.as_bytes()).await;
    let Some(release) = std::env::var_os("RUNNE_TEST_KILL_BOUNDARY_RELEASE") else {
        return;
    };
    let deadline = Instant::now() + Duration::from_secs(60);
    while !std::path::Path::new(&release).exists() {
        if Instant::now() >= deadline {
            break;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}
