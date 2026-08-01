#[cfg(not(unix))]
pub struct ProtectedActivationChannel;

#[cfg(not(unix))]
impl ProtectedActivationChannel {
    pub fn from_inherited_stdin() -> Result<Option<Self>, LaunchAuthorityError> {
        Ok(None)
    }
}
