use super::*;

impl Clock for StoreTransaction {
    fn now(&self) -> Result<Timestamp, ClockError> {
        let micros = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| ClockError::Unavailable)?
            .as_micros() as i64;
        Ok(Timestamp::from_unix_micros(micros))
    }
}
