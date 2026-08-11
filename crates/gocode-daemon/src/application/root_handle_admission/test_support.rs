use super::RootHandleAdmissionAuthority;

impl RootHandleAdmissionAuthority {
    /// Test-only observation of the exact opaque claim put on the control channel.
    pub fn take_test_admission(&self) -> Option<gocode_api::RootHandleAdmission> {
        let token = self.state.lock().ok()?.issued.take()?;
        gocode_api::RootHandleAdmission::decode_token(&token).ok()
    }
}
