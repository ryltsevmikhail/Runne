#![allow(dead_code)]
use core::fmt;
use gocode_provider_openai::canary::{AccountingDisposition, CanaryAccounting, TerminalUsage};

use super::{
    authority::ConsumedAttempt,
    fence::{Fence, FenceError, Observation, ObservationReport},
};

pub(super) const REPORT_STATUS: (&str, &str, &str) = ("NOT_RUN", "NOT_ACTIVATED", "NOT_ACCESSED");
macro_rules! closed_enum { ($name:ident { $($variant:ident),+ }) => { #[derive(Clone, Copy, Eq, PartialEq)] pub(super) enum $name { $($variant),+ } }; }
closed_enum!(LifecycleDisposition {
    NotRun,
    Terminal,
    Uncertain
});
closed_enum!(ReportDisposition {
    MissingUsage,
    NonterminalUsage,
    CachedUnderflow,
    Overflow,
    Underflow,
    PricingMismatch,
    SettlementMismatch,
    OverCap,
    Uncertain
});
macro_rules! closed {
    ($($type:ty => $name:literal),+ $(,)?) => { $(
        impl fmt::Debug for $type { fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { f.write_str($name) } }
        impl fmt::Display for $type { fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { f.write_str($name) } }
    )+ };
}
closed!(LifecycleDisposition => "LifecycleDisposition", ReportDisposition => "ReportDisposition");

pub(super) struct LifecycleReport {
    value: CanaryAccounting,
}

macro_rules! accounting_field { ($($name:ident: $type:ty),+ $(,)?) => { $(pub(super) const fn $name(&self) -> $type { self.value.$name() })+ }; }
impl LifecycleReport {
    fn from_accounting(value: CanaryAccounting) -> Self {
        Self { value }
    }
    accounting_field!(
        input_tokens: u64, output_tokens: u64, cached_input_tokens: u64,
        expected_cost_tenths: u64, reserved_tenths: u64, settled_tenths: u64,
        remaining_tenths: u64, settlement_count: u8, pricing_revision: &'static str,
        disposition: AccountingDisposition,
    );
}
impl fmt::Debug for LifecycleReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("LifecycleReport")
    }
}

#[derive(Clone, Copy)]
struct Settlement([u64; 4]);
enum AttemptObservation {
    None,
    Terminal(ConsumedAttempt),
    Uncertain(ConsumedAttempt),
}
pub(super) struct CanaryLifecycle {
    settlement: Option<Settlement>,
    disposition: LifecycleDisposition,
    observation: AttemptObservation,
}
impl Default for CanaryLifecycle {
    fn default() -> Self {
        Self {
            settlement: None,
            disposition: LifecycleDisposition::NotRun,
            observation: AttemptObservation::None,
        }
    }
}
impl fmt::Debug for CanaryLifecycle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("CanaryLifecycle")
    }
}
impl CanaryLifecycle {
    pub(super) fn reconcile(
        &mut self,
        usage: Option<TerminalUsage>,
        pricing: &str,
        reported_settled: u64,
    ) -> Result<LifecycleReport, ReportDisposition> {
        if self.disposition == LifecycleDisposition::Uncertain {
            return Err(ReportDisposition::Uncertain);
        }
        match &self.observation {
            AttemptObservation::Terminal(attempt) => {
                let _ = attempt;
            }
            AttemptObservation::None | AttemptObservation::Uncertain(_) => {
                return Err(ReportDisposition::Uncertain);
            }
        }
        let accounting = match usage {
            Some(usage) => CanaryAccounting::reconcile(usage, pricing),
            None => Err(AccountingDisposition::MissingUsage),
        };
        let accounting = match accounting {
            Ok(accounting) => accounting,
            Err(_) if self.settlement.is_some() => return self.uncertain(),
            Err(disposition) => return Err(map_accounting(disposition)),
        };
        if accounting.settled_tenths() != reported_settled {
            if self.settlement.is_some() {
                return self.uncertain();
            }
            return Err(ReportDisposition::SettlementMismatch);
        }
        let fingerprint = Settlement([
            accounting.input_tokens(),
            accounting.output_tokens(),
            accounting.cached_input_tokens(),
            accounting.settled_tenths(),
        ]);
        if let Some(previous) = self.settlement {
            if previous.0 != fingerprint.0 {
                return self.uncertain();
            }
        } else {
            self.settlement = Some(fingerprint);
            self.disposition = LifecycleDisposition::Terminal;
        }
        Ok(LifecycleReport::from_accounting(accounting))
    }
    pub(super) fn reject_nonterminal(&mut self) -> Result<LifecycleReport, ReportDisposition> {
        Err(ReportDisposition::NonterminalUsage)
    }
    pub(super) const fn disposition(&self) -> LifecycleDisposition {
        self.disposition
    }
    fn uncertain<T>(&mut self) -> Result<T, ReportDisposition> {
        self.disposition = LifecycleDisposition::Uncertain;
        Err(ReportDisposition::Uncertain)
    }
    pub(super) fn observe_terminal_after_possible_dispatch(
        &mut self,
        fence: &mut Fence,
    ) -> Result<(), FenceError> {
        self.ensure_observable()?;
        self.observation = AttemptObservation::Terminal(fence.consume_terminal_observation()?);
        Ok(())
    }
    pub(super) fn observe_after_possible_dispatch(
        &mut self,
        fence: &mut Fence,
        observation: Observation,
    ) -> Result<ObservationReport, FenceError> {
        self.ensure_observable()?;
        let attempt = fence.consume_uncertain_observation()?;
        let _ = observation;
        self.observation = AttemptObservation::Uncertain(attempt);
        self.disposition = LifecycleDisposition::Uncertain;
        Ok(ObservationReport {
            approvals_consumed: true,
            attempt_consumed: true,
        })
    }
    fn ensure_observable(&self) -> Result<(), FenceError> {
        if self.disposition == LifecycleDisposition::NotRun
            && self.settlement.is_none()
            && matches!(&self.observation, AttemptObservation::None)
        {
            Ok(())
        } else {
            Err(FenceError::InvalidTransition)
        }
    }
}
macro_rules! map_accounting { ($value:expr; $($name:ident),+) => { match $value { $(AccountingDisposition::$name => ReportDisposition::$name,)+ AccountingDisposition::Reconciled | AccountingDisposition::Uncertain => ReportDisposition::Uncertain } }; }
fn map_accounting(value: AccountingDisposition) -> ReportDisposition {
    map_accounting!(value; MissingUsage, NonterminalUsage, CachedUnderflow, Overflow, Underflow, PricingMismatch, SettlementMismatch, OverCap)
}
