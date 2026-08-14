#[cfg(any(test, feature = "fixture-only"))]
mod publication_effect_command;
#[cfg(any(test, feature = "fixture-only"))]
mod publication_effect_durable;
#[cfg(any(test, feature = "fixture-only"))]
mod publication_effect_durable_commands;
#[cfg(any(test, feature = "fixture-only"))]
mod publication_effect_durable_wire;
#[cfg(any(test, feature = "fixture-only"))]
mod publication_effect_evidence;
#[cfg(test)]
mod publication_effect_failpoint;
#[cfg(any(test, feature = "fixture-only"))]
mod publication_effect_intent;
#[cfg(any(test, feature = "fixture-only"))]
mod publication_effect_ledger;
#[cfg(any(test, feature = "fixture-only"))]
mod publication_effect_ledger_commands;
#[cfg(any(test, feature = "fixture-only"))]
mod publication_effect_ledger_preflight;
#[cfg(any(test, feature = "fixture-only"))]
mod publication_effect_ledger_recovery;
#[cfg(any(test, feature = "fixture-only"))]
mod publication_effect_types;

#[cfg(test)]
mod publication_effect_codec_tests;
#[cfg(test)]
mod publication_effect_durable_tests;
#[cfg(test)]
mod publication_effect_crash_tests;
#[cfg(test)]
mod publication_effect_preflight_tests;
#[cfg(test)]
mod publication_effect_outer_binding_tests;
#[cfg(test)]
mod publication_effect_replay_mutation_tests;
#[cfg(test)]
mod publication_effect_replay_tests;
#[cfg(test)]
mod publication_effect_tests;
