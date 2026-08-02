impl AuthorizedDeliveryGuard {
    fn revalidate(&self) -> Result<(), ReplayError> {
        let current = self.authorization.current_lease(&self.request)?;
        if current != self.lease {
            return Err(ReplayError::AuthorizationRevoked);
        }
        Ok(())
    }

    fn inspect_sensitivity(&self, event: &ReplayEvent) -> Result<(), ReplayError> {
        let event_sensitivity = match event.sensitivity {
            0 => Sensitivity::Public,
            1 => Sensitivity::Internal,
            2 => Sensitivity::Sensitive,
            _ => {
                return Err(ReplayError::Integrity(
                    "invalid delivered replay sensitivity".to_owned(),
                ));
            }
        };
        let rank = |value| match value {
            Sensitivity::Public => 0,
            Sensitivity::Internal => 1,
            Sensitivity::Sensitive => 2,
        };
        if rank(event_sensitivity) > rank(self.lease.sensitivity_ceiling()) {
            return Err(ReplayError::SensitivityDenied);
        }
        Ok(())
    }
}

impl ReplayDeliveryPrecommitGuard for AuthorizedDeliveryGuard {
    fn inspect(&self, session: &ReplaySession, events: &[ReplayEvent]) -> Result<(), ReplayError> {
        for event in events {
            self.inspect_sensitivity(event)?;
        }
        self.delegate.inspect(session, events)?;
        self.revalidate()
    }

    fn inspect_event(
        &self,
        session: &ReplaySession,
        event: &ReplayEvent,
    ) -> Result<(), ReplayError> {
        self.revalidate()?;
        self.inspect_sensitivity(event)?;
        self.delegate.inspect_event(session, event)?;
        self.revalidate()
    }

    fn inspect_ack(&self, session: &ReplaySession) -> Result<(), ReplayError> {
        self.delegate.inspect_ack(session)?;
        self.revalidate()
    }

    fn mutate_ack(
        &self,
        session: &ReplaySession,
        mutation: &mut dyn FnMut() -> Result<usize, ReplayError>,
    ) -> Result<usize, ReplayError> {
        self.authorization
            .mutate_with_current_lease(&self.request, &mut |current| {
                if current != &self.lease {
                    return Err(ReplayError::AuthorizationRevoked);
                }
                self.delegate.inspect_ack(session)?;
                mutation()
            })
    }
}
