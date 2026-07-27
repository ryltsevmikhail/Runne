#[derive(Debug, Clone)]
pub struct AuditRecord {
    pub event_type: AuditEventType,
    pub subject: String,
    pub action: String,
    pub outcome: String,
    pub timestamp: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuditEventType {
    AuthorizationDecision,
    SideEffectStarted,
    SideEffectConfirmed,
    SideEffectFailed,
    SideEffectUncertain,
    GrantIssued,
    GrantRevoked,
    SecretAccess,
}

pub struct AuditLogger {
    records: Vec<AuditRecord>,
    available: bool,
}

impl AuditLogger {
    pub fn new() -> Self {
        Self {
            records: Vec::new(),
            available: true,
        }
    }

    pub fn record(&mut self, record: AuditRecord) -> Result<(), AuditError> {
        if !self.available {
            return Err(AuditError::StoreUnavailable);
        }
        self.records.push(record);
        Ok(())
    }

    pub fn set_unavailable(&mut self) {
        self.available = false;
    }

    pub fn records(&self) -> &[AuditRecord] {
        &self.records
    }
}

impl Default for AuditLogger {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, thiserror::Error)]
pub enum AuditError {
    #[error("audit store unavailable")]
    StoreUnavailable,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn audit_store_unavailable_rejects_record() {
        let mut logger = AuditLogger::new();
        logger.set_unavailable();
        let result = logger.record(AuditRecord {
            event_type: AuditEventType::AuthorizationDecision,
            subject: "test".into(),
            action: "fs:read".into(),
            outcome: "allow".into(),
            timestamp: 0,
        });
        assert!(result.is_err());
    }

    #[test]
    fn audit_records_preserved() {
        let mut logger = AuditLogger::new();
        logger
            .record(AuditRecord {
                event_type: AuditEventType::SideEffectStarted,
                subject: "task1".into(),
                action: "fs:write".into(),
                outcome: "started".into(),
                timestamp: 1,
            })
            .unwrap();
        assert_eq!(logger.records().len(), 1);
    }
}
