use super::*;

pub(super) fn measure_launched_executable() -> Result<ExecutableIdentityV1, DaemonError> {
    let path = std::env::current_exe()
        .map_err(|_| DaemonError::Bootstrap("measure launched executable".into()))?;
    ExecutableIdentityV1::measure(&path)
        .map_err(|_| DaemonError::Bootstrap("measure launched executable".into()))
}
