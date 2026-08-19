/// Durable exactly-once authority for hook intents and outcomes.
pub trait PluginHookDispatchAuthorityPort {
    /// Atomically validates the active binding and claims an exact request.
    fn claim(
        &self,
        activation: &PluginActivationSnapshot,
        definition: &PluginHookDefinition,
        invocation: &PluginHookInvocation,
        request_digest: [u8; 32],
    ) -> Result<PluginHookDispatchClaimResult, PluginHookDispatchError>;

    /// Durably closes a fresh claim before its outcome reaches the caller.
    fn complete(
        &self,
        claim: PluginHookDispatchClaim,
        disposition: PluginHookDisposition,
    ) -> Result<(), PluginHookDispatchError>;

    /// Quarantines one recovered open intent as `Uncertain` without plugin IPC.
    ///
    /// Stronger dispositions require a separate typed evidence boundary and
    /// cannot be forged through crash recovery.
    fn quarantine_recovered(
        &self,
        recovered: &PluginHookRecoveredDispatch,
    ) -> Result<(), PluginHookDispatchError>;
}

/// Freezes a global descriptor list in canonical
/// `(priority, plugin_id, hook_id)` order before per-activation routing.
pub fn ordered_plugin_hooks(
    definitions: &[PluginHookDefinition],
) -> Result<Box<[PluginHookDefinition]>, PluginHookDispatchError> {
    if definitions.len() > MAX_PLUGIN_HOOK_DEFINITIONS {
        return Err(PluginHookDispatchError::TooManyDefinitions);
    }
    let mut ordered = definitions.to_vec();
    ordered.sort_by(compare_hooks);
    Ok(ordered.into_boxed_slice())
}

/// Dispatches one activation-owned frozen descriptor set through the plugin
/// transport. Multi-plugin orchestration calls this boundary once per exact
/// activation after sorting the global descriptor snapshot.
pub fn dispatch_hooks(
    descriptors: &VerifiedPluginHookDescriptors,
    invocation: &PluginHookInvocation,
    activation: &PluginActivationSnapshot,
    generations: &dyn PluginGenerationPort,
    dispatches: &dyn PluginHookDispatchAuthorityPort,
    clock: &dyn PluginHookClockPort,
    transport: &mut dyn PluginTransportPort,
) -> Result<PluginHookDispatch, PluginHookDispatchError> {
    if descriptors.activation_id != *activation.activation_id()
        || descriptors.package_digest != activation.package_digest()
        || descriptors.generation != activation.generation()
    {
        return Err(PluginHookDispatchError::DescriptorUnverified);
    }

    let mut allowed = true;
    let mut channel_uncertain = false;
    let mut results = Vec::with_capacity(descriptors.definitions.len());
    for definition in descriptors.definitions.iter().cloned() {
        let current = clock.now_tick();
        let dispatchable = activation.is_dispatchable(generations);
        let disposition = if channel_uncertain || !dispatchable {
            PluginHookDisposition::Denied
        } else if current >= invocation.deadline_tick {
            PluginHookDisposition::Failed
        } else {
            dispatch_one(
                &definition,
                descriptors.descriptor_snapshot_digest,
                invocation,
                activation,
                dispatches,
                transport,
            )?
        };
        if disposition == PluginHookDisposition::Uncertain {
            channel_uncertain = true;
        }
        if definition.failure_policy != PluginHookFailurePolicy::Optional
            && disposition != PluginHookDisposition::Completed
        {
            allowed = false;
        }
        results.push(PluginHookResult {
            definition,
            disposition,
        });
    }
    Ok(PluginHookDispatch {
        results: results.into_boxed_slice(),
        guarded_operation_allowed: allowed,
    })
}

fn compare_hooks(left: &PluginHookDefinition, right: &PluginHookDefinition) -> core::cmp::Ordering {
    (
        left.priority,
        left.plugin_id.as_str(),
        left.hook_id.as_str(),
    )
        .cmp(&(
            right.priority,
            right.plugin_id.as_str(),
            right.hook_id.as_str(),
        ))
}

fn dispatch_one(
    definition: &PluginHookDefinition,
    descriptor_snapshot_digest: [u8; 32],
    invocation: &PluginHookInvocation,
    activation: &PluginActivationSnapshot,
    dispatches: &dyn PluginHookDispatchAuthorityPort,
    transport: &mut dyn PluginTransportPort,
) -> Result<PluginHookDisposition, PluginHookDispatchError> {
    let (outbound, request_digest) = encode_hook_request(
        definition,
        descriptor_snapshot_digest,
        invocation,
        activation,
    );
    let claim = match dispatches.claim(activation, definition, invocation, request_digest)? {
        PluginHookDispatchClaimResult::Fresh(claim) => claim,
        PluginHookDispatchClaimResult::Existing(disposition) => return Ok(disposition),
    };
    match transport.send_before(
        invocation.deadline_tick,
        PluginBootstrapFrame::outbound(outbound),
    ) {
        Ok(()) => {}
        Err(PluginTransportPortError::NotSent) => {
            dispatches.complete(claim, PluginHookDisposition::Failed)?;
            return Ok(PluginHookDisposition::Failed);
        }
        Err(
            PluginTransportPortError::Unavailable
            | PluginTransportPortError::ResponseLost
            | PluginTransportPortError::DeadlineExceeded,
        ) => {
            dispatches.complete(claim, PluginHookDisposition::Uncertain)?;
            return Ok(PluginHookDisposition::Uncertain);
        }
    };
    let mut response = [0u8; HOOK_RESPONSE_BYTES];
    let received = match transport.receive_before(invocation.deadline_tick, &mut response) {
        Ok(received) if received == HOOK_RESPONSE_BYTES => received,
        Ok(_) | Err(_) => {
            dispatches.complete(claim, PluginHookDisposition::Uncertain)?;
            return Ok(PluginHookDisposition::Uncertain);
        }
    };
    let disposition = if response[..32] != request_digest {
        PluginHookDisposition::Uncertain
    } else {
        match response[received - 1] {
            0 => PluginHookDisposition::Completed,
            1 => PluginHookDisposition::Denied,
            2 => PluginHookDisposition::Failed,
            3 => PluginHookDisposition::Uncertain,
            _ => PluginHookDisposition::Uncertain,
        }
    };
    dispatches.complete(claim, disposition)?;
    Ok(disposition)
}

fn encode_hook_request(
    definition: &PluginHookDefinition,
    descriptor_snapshot_digest: [u8; 32],
    invocation: &PluginHookInvocation,
    activation: &PluginActivationSnapshot,
) -> (Vec<u8>, [u8; 32]) {
    let mut encoded = Vec::with_capacity(256 + invocation.payload.len());
    encode_text(&mut encoded, invocation.invocation_id.as_str());
    encode_text(&mut encoded, activation.activation_id().as_str());
    encoded.extend_from_slice(&activation.generation().get().to_be_bytes());
    encoded.extend_from_slice(activation.negotiation_snapshot().as_bytes());
    encode_text(&mut encoded, definition.plugin_id.as_str());
    encode_text(&mut encoded, definition.hook_id.as_str());
    encoded.extend_from_slice(&descriptor_snapshot_digest);
    encoded.extend_from_slice(&invocation.deadline_tick.to_be_bytes());
    encoded.extend_from_slice(invocation.payload_digest());
    encoded.extend_from_slice(&(invocation.payload.len() as u64).to_be_bytes());
    encoded.extend_from_slice(&invocation.payload);
    let request_digest = request_digest(&encoded);
    encoded.extend_from_slice(&request_digest);
    (encoded, request_digest)
}

fn encode_text(encoded: &mut Vec<u8>, value: &str) {
    encoded.extend_from_slice(&(value.len() as u16).to_be_bytes());
    encoded.extend_from_slice(value.as_bytes());
}

fn hook_payload_digest(payload: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(HOOK_PAYLOAD_DIGEST_DOMAIN);
    hasher.update((payload.len() as u64).to_be_bytes());
    hasher.update(payload);
    hasher.finalize().into()
}

fn hook_descriptor_digest(definitions: &[PluginHookDefinition]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"RUNNE_PLUGIN_HOOK_DESCRIPTOR_SNAPSHOT_V1\0");
    hasher.update((definitions.len() as u64).to_be_bytes());
    for definition in definitions {
        hasher.update(definition.priority.to_be_bytes());
        hasher.update((definition.plugin_id.as_str().len() as u64).to_be_bytes());
        hasher.update(definition.plugin_id.as_str().as_bytes());
        hasher.update((definition.hook_id.as_str().len() as u64).to_be_bytes());
        hasher.update(definition.hook_id.as_str().as_bytes());
        hasher.update([match definition.failure_policy {
            PluginHookFailurePolicy::Optional => 0,
            PluginHookFailurePolicy::Required => 1,
            PluginHookFailurePolicy::Security => 2,
        }]);
    }
    hasher.finalize().into()
}

fn request_digest(request: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(HOOK_REQUEST_DIGEST_DOMAIN);
    hasher.update((request.len() as u64).to_be_bytes());
    hasher.update(request);
    hasher.finalize().into()
}
