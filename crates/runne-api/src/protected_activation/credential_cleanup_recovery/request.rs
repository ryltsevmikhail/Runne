use super::*;
const REQUEST: u8 = 3;

impl ProtectedCredentialRecoveryCodec {
    /// Selects a pending operation through the protected channel; not effect authority.
    pub fn encode_desktop_request(
        &mut self,
        operation: [u8; 16],
    ) -> Result<Vec<u8>, LaunchAuthorityError> {
        self.require_initial_request()?;
        if operation == [0; 16] {
            return Err(LaunchAuthorityError::InvalidContract);
        }
        let mut payload = self.bootstrap.digest().to_vec();
        payload.extend_from_slice(&operation);
        let frame = self.encode(REQUEST, &payload)?;
        self.requested_operation = Some(operation);
        Ok(frame)
    }

    /// Authenticates the first recovery request before the host loads the operation.
    pub fn decode_desktop_request(
        &mut self,
        frame: &[u8],
    ) -> Result<[u8; 16], LaunchAuthorityError> {
        self.require_initial_request()?;
        let payload = self.decode(frame, REQUEST, 48)?;
        let operation: [u8; 16] = payload[32..].try_into().unwrap();
        if !bool::from(payload[..32].ct_eq(&self.bootstrap.digest())) || operation == [0; 16] {
            return Err(LaunchAuthorityError::InvalidContract);
        }
        self.received += 1;
        self.requested_operation = Some(operation);
        Ok(operation)
    }

    fn require_initial_request(&self) -> Result<(), LaunchAuthorityError> {
        if self.sent != 0 || self.received != 0 || self.requested_operation.is_some() {
            return Err(LaunchAuthorityError::InvalidContract);
        }
        Ok(())
    }

    pub(super) fn require_requested_operation(
        &self,
        operation: [u8; 16],
    ) -> Result<(), LaunchAuthorityError> {
        if self
            .requested_operation
            .is_some_and(|expected| expected != operation)
        {
            return Err(LaunchAuthorityError::InvalidContract);
        }
        Ok(())
    }
}
