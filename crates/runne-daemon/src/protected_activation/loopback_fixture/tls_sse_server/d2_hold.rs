pub(super) async fn hold_final_stop<S>(stream: &mut S, response: &[u8]) -> Result<usize, ()>
where
    S: tokio::io::AsyncWrite + Unpin,
{
    use tokio::io::AsyncWriteExt as _;
    let Some(prefix) = response
        .windows(b"event: response.completed".len())
        .position(|window| window == b"event: response.completed")
    else {
        return Err(());
    };
    if std::env::var("RUNNE_TEST_T1_TRUST_COMPOSITION").as_deref() != Ok("1")
        || !matches!(
            std::env::var("RUNNE_TEST_D2_TOOL_SCENARIO").as_deref(),
            Ok("cancel-final-response" | "stale-final-target")
        )
        || prefix == 0
        || prefix >= response.len()
    {
        return Err(());
    }
    let Some(directory) = std::env::var_os("RUNNE_TEST_D2_PROVIDER_BARRIER_DIR")
        .map(std::path::PathBuf::from)
        .filter(|path| path.is_absolute() && path.is_dir())
    else {
        return Err(());
    };
    stream
        .write_all(&response[..prefix])
        .await
        .map_err(|_| ())?;
    let entered = directory.join("provider-final-stop.entered");
    let release = directory.join("provider-final-stop.release");
    tokio::fs::write(&entered, b"prefix-delivered")
        .await
        .map_err(|_| ())?;
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(25);
    while !release.is_file() {
        if tokio::time::Instant::now() >= deadline {
            return Err(());
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    tokio::time::sleep(std::time::Duration::from_millis(150)).await;
    Ok(prefix)
}
