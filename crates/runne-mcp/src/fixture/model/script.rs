/// One immutable virtual-clock script step.
#[derive(Clone, PartialEq)]
pub struct FixtureStep {
    pub(crate) available_at_tick: u64,
    pub(crate) outcome: FixtureStepOutcome,
}

/// Deterministic effect-boundary outcome.
#[derive(Clone, PartialEq)]
pub(crate) enum FixtureStepOutcome {
    Response(Value), ProtocolError, CancelBeforeDispatch, DisconnectBeforeDispatch,
    AcceptedThenLost, AccountingMismatch, StaleResponse,
}

impl FixtureStep {
    /// Returns a bounded successful response available at a virtual clock tick.
    pub fn response_at(tick: u64, value: Value) -> Result<Self, FixtureMcpFailure> {
        super::schema::validate_value(&value, &FixtureLimits::default()).map_err(|_| FixtureMcpFailure::ResponseTooLarge)?;
        super::schema::reject_secret_material(&value)?;
        Ok(Self { available_at_tick: tick, outcome: FixtureStepOutcome::Response(value) })
    }
    /// Returns a protocol error before any terminal proof.
    pub const fn protocol_error_at(tick: u64) -> Self { Self { available_at_tick: tick, outcome: FixtureStepOutcome::ProtocolError } }
    /// Returns a cancellation observed before dispatch.
    pub const fn cancel_before_dispatch_at(tick: u64) -> Self { Self { available_at_tick: tick, outcome: FixtureStepOutcome::CancelBeforeDispatch } }
    /// Returns a disconnect observed before dispatch.
    pub const fn disconnect_before_dispatch_at(tick: u64) -> Self { Self { available_at_tick: tick, outcome: FixtureStepOutcome::DisconnectBeforeDispatch } }
    /// Returns accepted work without terminal proof.
    pub const fn accepted_then_lost_at(tick: u64) -> Self { Self { available_at_tick: tick, outcome: FixtureStepOutcome::AcceptedThenLost } }
    /// Returns a synthetic settlement mismatch after dispatch.
    pub const fn accounting_mismatch_at(tick: u64) -> Self { Self { available_at_tick: tick, outcome: FixtureStepOutcome::AccountingMismatch } }
    /// Returns a response belonging to the old connection.
    pub const fn stale_response_at(tick: u64) -> Self { Self { available_at_tick: tick, outcome: FixtureStepOutcome::StaleResponse } }
}

/// Immutable bounded deterministic transport script.
#[derive(Clone, PartialEq)]
pub struct FixtureScript { pub(crate) steps: Box<[FixtureStep]>, digest: [u8; 32] }

impl FixtureScript {
    /// Freezes a monotonically ordered bounded step sequence.
    pub fn new(steps: Vec<FixtureStep>) -> Result<Self, FixtureMcpFailure> {
        if steps.is_empty() || steps.len() > MAX_SCRIPT_STEPS || steps.windows(2).any(|pair| pair[0].available_at_tick > pair[1].available_at_tick) {
            return Err(FixtureMcpFailure::ToolDefinitionInvalid);
        }
        let mut encoded = Vec::new();
        for step in &steps {
            encoded.extend_from_slice(&step.available_at_tick.to_be_bytes());
            match &step.outcome {
                FixtureStepOutcome::Response(value) => {
                    encoded.push(0);
                    let response = serde_json::to_vec(value).map_err(|_| FixtureMcpFailure::ToolDefinitionInvalid)?;
                    encoded.extend_from_slice(&(response.len() as u64).to_be_bytes());
                    encoded.extend_from_slice(&response);
                }
                FixtureStepOutcome::ProtocolError => encoded.push(1),
                FixtureStepOutcome::CancelBeforeDispatch => encoded.push(2),
                FixtureStepOutcome::DisconnectBeforeDispatch => encoded.push(3),
                FixtureStepOutcome::AcceptedThenLost => encoded.push(4),
                FixtureStepOutcome::AccountingMismatch => encoded.push(5),
                FixtureStepOutcome::StaleResponse => encoded.push(6),
            }
        }
        Ok(Self { steps: steps.into_boxed_slice(), digest: digest_domain(b"GOCODE_MCP_FIXTURE_SCRIPT_V1\0", &[&encoded]) })
    }
    /// Returns the versioned opaque script digest.
    pub const fn digest(&self) -> [u8; 32] { self.digest }
}
