use super::{MetadataQueryError, identity::EPOCH_CAP};
pub(super) struct OwnerState {
    pub(super) epoch: u64,
    pub(super) closed: bool,
}
impl OwnerState {
    pub(super) fn close(&mut self, expected: u64) -> Result<(), MetadataQueryError> {
        if self.closed {
            return Ok(());
        }
        if expected != self.epoch {
            return Err(MetadataQueryError::StaleGeneration);
        }
        self.closed = true;
        match self.epoch.checked_add(1) {
            Some(next) if next <= EPOCH_CAP => {
                self.epoch = next;
                Ok(())
            }
            _ => Err(MetadataQueryError::InternalUnavailable),
        }
    }
}
