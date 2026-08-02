impl PluginActivationSnapshot {
    pub fn reconcile_process(
        mut self,
        process: &mut dyn PluginProcessPort,
    ) -> Result<Self, Box<(Self, PluginLifecycleError)>> {
        if self.state != ActivationState::Uncertain {
            return Err(Box::new((self, PluginLifecycleError::InvalidTransition)));
        }
        let (Some(start_intent), Some(generation_lease)) =
            (self.start_intent.as_ref(), self.generation_lease.as_ref())
        else {
            return Err(Box::new((self, PluginLifecycleError::InvalidTransition)));
        };
        let mut receipts = self.receipts.to_vec();
        receipts.push(PluginActivationReceipt::ReconciliationAttempted);
        match process.reconcile(start_intent, generation_lease) {
            Ok(PluginStartReconciliation::NotStarted) => {
                receipts.push(PluginActivationReceipt::StartProvenNotStarted);
                self.state = ActivationState::Verified;
                self.start_intent = None;
                self.process_lease = None;
                self.generation_lease = None;
                self.active_fence = None;
                self.record(ActivationState::Verified);
                self.receipts = Self::bounded_receipts(receipts);
                Ok(self)
            }
            Ok(PluginStartReconciliation::Started(lease))
                if lease.matches(
                    self.start_intent
                        .as_ref()
                        .expect("start intent is retained while reconciling"),
                ) =>
            {
                self.process_lease = Some(lease);
                self.receipts = Self::bounded_receipts(receipts);
                Ok(self)
            }
            Ok(PluginStartReconciliation::Started(_) | PluginStartReconciliation::Uncertain)
            | Err(_) => {
                self.receipts = Self::bounded_receipts(receipts);
                Ok(self)
            }
        }
    }

    fn record(&mut self, state: ActivationState) {
        let mut history = self.history.to_vec();
        history.push(state);
        self.history = history.into_boxed_slice();
    }


}
