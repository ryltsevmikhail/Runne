impl PluginActivationRequest {
    pub fn activate_with_reservation(
        &self,
        process: &mut dyn PluginProcessPort,
        transport: &mut dyn PluginTransportPort,
        generations: &dyn PluginGenerationPort,
        start_intents: &dyn PluginStartIntentPort,
    ) -> PluginActivationSnapshot {
        let generation = self.package.generation();
        let generation_lease = match generations.acquire_read_lease(&self.activation_id) {
            Ok(lease) if lease.matches(&self.activation_id, generation) => lease,
            _ => return PluginActivationSnapshot::pre_start(self, ActivationState::Verified),
        };
        let start_intent = match start_intents.reserve(
            &self.activation_id,
            self.package.package_digest(),
            generation,
        ) {
            Ok(intent)
                if intent.matches(
                    &self.activation_id,
                    self.package.package_digest(),
                    generation,
                ) =>
            {
                intent
            }
            _ => return PluginActivationSnapshot::pre_start(self, ActivationState::Verified),
        };
        debug_assert!(start_intent.matches(
            &self.activation_id,
            self.package.package_digest(),
            generation
        ));
        let mut receipt_values = Vec::new();
        let process_result = if start_intent.origin() == PluginStartIntentOrigin::Existing {
            receipt_values.push(PluginActivationReceipt::ReconciliationAttempted);
            match process.reconcile(&start_intent, &generation_lease) {
                Ok(PluginStartReconciliation::Started(lease)) => Ok(lease),
                Ok(PluginStartReconciliation::NotStarted) => {
                    receipt_values.push(PluginActivationReceipt::StartProvenNotStarted);
                    receipt_values.push(PluginActivationReceipt::StartAttempted);
                    process.start(&start_intent, &generation_lease)
                }
                Ok(PluginStartReconciliation::Uncertain) | Err(_) => {
                    return PluginActivationSnapshot::started(
                        self,
                        StartedActivation {
                            state: ActivationState::Uncertain,
                            start_intent,
                            process_lease: None,
                            generation_lease,
                            active_fence: None,
                            negotiated: false,
                            receipts: PluginActivationSnapshot::bounded_receipts(receipt_values),
                        },
                    );
                }
            }
        } else {
            receipt_values.push(PluginActivationReceipt::StartAttempted);
            process.start(&start_intent, &generation_lease)
        };
        let receipts = PluginActivationSnapshot::bounded_receipts(receipt_values);
        let process_lease = match process_result {
            Ok(lease) if lease.matches(&start_intent) => lease,
            Ok(_) | Err(PluginProcessPortError::ResponseLost) => {
                return PluginActivationSnapshot::started(
                    self,
                    StartedActivation {
                        state: ActivationState::Uncertain,
                        start_intent,
                        process_lease: None,
                        generation_lease,
                        active_fence: None,
                        negotiated: false,
                        receipts,
                    },
                );
            }
            Err(PluginProcessPortError::BackendUnavailable | PluginProcessPortError::Rejected) => {
                let mut receipt_values = receipts.to_vec();
                receipt_values.push(PluginActivationReceipt::StartProvenNotStarted);
                let snapshot = PluginActivationSnapshot {
                    receipts: PluginActivationSnapshot::bounded_receipts(receipt_values),
                    ..PluginActivationSnapshot::pre_start(self, ActivationState::Verified)
                };
                return snapshot;
            }
        };
        let uncertain = |start_intent, lease, generation_lease, negotiated| {
            PluginActivationSnapshot::started(
                self,
                StartedActivation {
                    state: ActivationState::Uncertain,
                    start_intent,
                    process_lease: lease,
                    generation_lease,
                    active_fence: None,
                    negotiated,
                    receipts: receipts.clone(),
                },
            )
        };
        let hello = match self.exchange_host_hello(transport) {
            Some(value) => value,
            None => return uncertain(start_intent, Some(process_lease), generation_lease, true),
        };
        let plugin_nonce = match self.validate_plugin_hello(&hello) {
            Some(value) => value,
            None => return uncertain(start_intent, Some(process_lease), generation_lease, true),
        };
        if !self.exchange_profile_selection(transport, plugin_nonce) {
            return uncertain(start_intent, Some(process_lease), generation_lease, true);
        }
        let active_fence = match generations
            .publish_active(&generation_lease, self.package.negotiation_snapshot())
        {
            Ok(fence)
                if fence.matches(
                    &self.activation_id,
                    generation,
                    self.package.negotiation_snapshot(),
                ) =>
            {
                fence
            }
            _ => return uncertain(start_intent, Some(process_lease), generation_lease, true),
        };
        PluginActivationSnapshot::started(
            self,
            StartedActivation {
                state: ActivationState::Active,
                start_intent,
                process_lease: Some(process_lease),
                generation_lease,
                active_fence: Some(active_fence),
                negotiated: true,
                receipts,
            },
        )
    }


}
