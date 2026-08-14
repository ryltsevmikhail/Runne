use super::{
    Duration, Future, LIVE_RESET_INTERVAL, Pin, RECONNECT_DELAYS, ReplayRetentionBaselineV1,
    ReplayRetentionBaselineV2, fmt,
};

/// Closed recovery state consumed by `AppCore`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReplayRecoveryDisposition {
    Reconnectable,
    Incompatible,
    ResyncRequired,
    Revoked,
    Fatal,
}

/// Stable replay-client failure condition.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReplayClientErrorKind {
    InvalidRequest,
    Transport,
    StreamSilence,
    Backpressure,
    SessionExpired,
    PeerIdentityMismatch,
    BindingMismatch,
    SchemaMismatch,
    RetentionGap,
    SensitivityDenied,
    AuthorizationRevoked,
    CursorInvalid,
    AggregateMismatch,
    NonMonotonicSequence,
    EventIdentityConflict,
    Integrity,
    LocalCallback,
    ResponseTooLarge,
    UnexpectedContentType,
    InvalidResponse,
}

impl ReplayClientErrorKind {
    #[must_use]
    pub const fn recovery_disposition(self) -> ReplayRecoveryDisposition {
        match self {
            Self::Transport | Self::StreamSilence | Self::Backpressure | Self::SessionExpired => {
                ReplayRecoveryDisposition::Reconnectable
            }
            Self::PeerIdentityMismatch
            | Self::BindingMismatch
            | Self::SchemaMismatch
            | Self::UnexpectedContentType
            | Self::InvalidResponse => ReplayRecoveryDisposition::Incompatible,
            // A verified retention baseline is exposed for Task 11 consumption
            // only; Task 10 must not authorize local reset or promotion.
            Self::RetentionGap
            | Self::InvalidRequest
            | Self::CursorInvalid
            | Self::AggregateMismatch
            | Self::NonMonotonicSequence
            | Self::EventIdentityConflict
            | Self::Integrity
            | Self::LocalCallback
            | Self::ResponseTooLarge => ReplayRecoveryDisposition::Fatal,
            Self::SensitivityDenied | Self::AuthorizationRevoked => {
                ReplayRecoveryDisposition::Revoked
            }
        }
    }
}

/// Typed redacted replay-client failure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReplayClientError {
    kind: ReplayClientErrorKind,
    baseline: Option<Box<ReplayRetentionBaselineV1>>,
    baseline_v2: Option<Box<ReplayRetentionBaselineV2>>,
}

impl ReplayClientError {
    pub(super) const fn new(kind: ReplayClientErrorKind) -> Self {
        Self {
            kind,
            baseline: None,
            baseline_v2: None,
        }
    }

    pub(super) fn retention_gap(baseline: ReplayRetentionBaselineV1) -> Self {
        Self {
            kind: ReplayClientErrorKind::RetentionGap,
            baseline: Some(Box::new(baseline)),
            baseline_v2: None,
        }
    }

    #[must_use]
    pub const fn kind(&self) -> ReplayClientErrorKind {
        self.kind
    }

    #[must_use]
    pub fn retention_baseline(&self) -> Option<&ReplayRetentionBaselineV1> {
        self.baseline.as_deref()
    }
    /// Returns a verified V2 resume baseline only when the server supplied one.
    #[must_use]
    pub fn retention_baseline_v2(&self) -> Option<&ReplayRetentionBaselineV2> {
        self.baseline_v2.as_deref()
    }
    pub(super) fn retention_gap_v2(baseline: ReplayRetentionBaselineV2) -> Self {
        Self {
            kind: ReplayClientErrorKind::RetentionGap,
            baseline: None,
            baseline_v2: Some(Box::new(baseline)),
        }
    }

    #[must_use]
    pub const fn recovery_disposition(&self) -> ReplayRecoveryDisposition {
        self.kind.recovery_disposition()
    }
}

impl fmt::Display for ReplayClientError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self.kind.recovery_disposition() {
            ReplayRecoveryDisposition::Reconnectable => "runtime replay is temporarily unavailable",
            ReplayRecoveryDisposition::Incompatible => "runtime replay is incompatible",
            ReplayRecoveryDisposition::ResyncRequired => "runtime replay requires explicit resync",
            ReplayRecoveryDisposition::Revoked => "runtime replay authorization was revoked",
            ReplayRecoveryDisposition::Fatal => "runtime replay failed safely",
        })
    }
}

impl std::error::Error for ReplayClientError {}

/// Deterministic reconnect decision.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReconnectDecision {
    RetryAfter(Duration),
    Exhausted,
}

/// Injectable monotonic clock and sleeper for deterministic reconnect tests.
pub trait ReconnectRuntime: Sync {
    fn now(&self) -> Duration;

    fn sleep(&self, delay: Duration) -> Pin<Box<dyn Future<Output = ()> + Send + '_>>;
}

/// Bounded deterministic reconnect policy.
#[derive(Clone, Debug, Default)]
pub struct ReconnectPolicy {
    attempts: usize,
    live_since: Option<Duration>,
}

impl ReconnectPolicy {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            attempts: 0,
            live_since: None,
        }
    }

    #[must_use]
    pub fn record_failure(&mut self) -> ReconnectDecision {
        self.live_since = None;
        let Some(delay) = RECONNECT_DELAYS.get(self.attempts).copied() else {
            return ReconnectDecision::Exhausted;
        };
        self.attempts = self.attempts.saturating_add(1);
        ReconnectDecision::RetryAfter(delay)
    }

    pub fn record_live_delivery(&mut self, now: Duration) {
        let started = *self.live_since.get_or_insert(now);
        if now.saturating_sub(started) >= LIVE_RESET_INTERVAL {
            self.attempts = 0;
            self.live_since = Some(now);
        }
    }

    pub fn record_live_delivery_with(&mut self, runtime: &impl ReconnectRuntime) {
        self.record_live_delivery(runtime.now());
    }

    pub async fn wait_after_failure(
        &mut self,
        runtime: &impl ReconnectRuntime,
    ) -> ReconnectDecision {
        let decision = self.record_failure();
        if let ReconnectDecision::RetryAfter(delay) = decision {
            runtime.sleep(delay).await;
        }
        decision
    }
}
