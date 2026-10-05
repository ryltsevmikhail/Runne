use super::protocol::BindingV1;
use std::ffi::CString;

pub(super) fn valid_path(path: String) -> Result<CString, &'static str> {
    if path.is_empty()
        || path.len() > 255
        || path == "."
        || path == ".."
        || path.contains('/')
        || path.contains('\\')
        || path.as_bytes().contains(&0)
    {
        return Err("path_denied");
    }
    CString::new(path).map_err(|_| "path_denied")
}

pub(super) fn validate_binding(binding: &BindingV1) -> Result<(), &'static str> {
    let bounded = |value: &str| {
        !value.is_empty()
            && value.len() <= 64
            && value
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() || byte == b'-')
    };
    if !bounded(&binding.taskrun_id)
        || !bounded(&binding.attempt_id)
        || !bounded(&binding.cycle_id)
        || !bounded(&binding.invocation_digest)
        || !bounded(&binding.environment_digest)
        || !bounded(&binding.approval_digest)
        || binding.taskrun_version == 0
        || binding.assignment_fence == 0
        || binding.expires_at_unix_ms
            <= std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_err(|_| "clock_invalid")?
                .as_millis() as u64
    {
        return Err("binding_invalid_or_expired");
    }
    Ok(())
}
