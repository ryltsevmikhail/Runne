use super::*;
use crate::{ProviderCredentialOperationSnapshotV2, ProviderCredentialOperationStateV2};

const TERMINAL: u8 = 4;
const MAX_SNAPSHOT: usize = 4096;

impl ProtectedCredentialRecoveryCodec {
    /// Safe observation bound to the accepted attempt, not permission for effects.
    /// Completion may arrive after the admission lease; it grants no new lease.
    pub fn encode_daemon_terminal(
        &mut self,
        snapshot: &ProviderCredentialOperationSnapshotV2,
    ) -> Result<Vec<u8>, LaunchAuthorityError> {
        let digest = self.require_terminal_binding()?;
        require_terminal(snapshot)?;
        let bytes =
            serde_json::to_vec(snapshot).map_err(|_| LaunchAuthorityError::InvalidContract)?;
        if bytes.len() > MAX_SNAPSHOT {
            return Err(LaunchAuthorityError::InvalidContract);
        }
        let mut payload = digest.to_vec();
        payload.extend_from_slice(&bytes);
        let frame = self.encode(TERMINAL, &payload)?;
        self.terminal = true;
        Ok(frame)
    }

    /// Verifies the exact accepted offer, canonical safe projection and terminal state.
    pub fn decode_daemon_terminal(
        &mut self,
        frame: &[u8],
    ) -> Result<ProviderCredentialOperationSnapshotV2, LaunchAuthorityError> {
        let digest = self.require_terminal_binding()?;
        let payload_len = frame
            .len()
            .checked_sub(4 + HEADER + 32)
            .filter(|length| (33..=32 + MAX_SNAPSHOT).contains(length))
            .ok_or(LaunchAuthorityError::InvalidContract)?;
        let payload = self.decode(frame, TERMINAL, payload_len)?;
        if !bool::from(payload[..32].ct_eq(&digest)) {
            return Err(LaunchAuthorityError::InvalidContract);
        }
        let snapshot = super::super::decode_canonical_json(&payload[32..])?;
        require_terminal(&snapshot)?;
        self.received += 1;
        self.terminal = true;
        Ok(snapshot)
    }

    fn require_terminal_binding(&self) -> Result<[u8; 32], LaunchAuthorityError> {
        if self.terminal {
            return Err(LaunchAuthorityError::InvalidContract);
        }
        self.accepted_offer
            .ok_or(LaunchAuthorityError::InvalidContract)
    }
}

fn require_terminal(
    snapshot: &ProviderCredentialOperationSnapshotV2,
) -> Result<(), LaunchAuthorityError> {
    if matches!(
        snapshot.state(),
        ProviderCredentialOperationStateV2::Completed
            | ProviderCredentialOperationStateV2::Failed
            | ProviderCredentialOperationStateV2::Expired
            | ProviderCredentialOperationStateV2::Cancelled
            | ProviderCredentialOperationStateV2::Tombstoned
    ) {
        Ok(())
    } else {
        Err(LaunchAuthorityError::InvalidContract)
    }
}
