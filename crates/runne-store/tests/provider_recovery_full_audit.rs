#![allow(dead_code)]

#[path = "support/online_credential_fixture.rs"]
mod online_credential_fixture;
#[path = "support/online_proof.rs"]
mod online_proof;
#[path = "support/online_stream_fixture.rs"]
mod online_stream_fixture;
#[path = "support/provider_credential_fixture.rs"]
mod provider_credential_fixture;
#[path = "provider_recovery_full_audit_parts/runtime_config.rs"]
mod runtime_config;
#[path = "provider_recovery_full_audit_parts/sql_snapshot.rs"]
mod sql_snapshot;
use runtime_config::runtime_config;
use sql_snapshot::{SqlSnapshot, sql_snapshot, sql_table_rows};
#[path = "support/validated_reopen.rs"]
mod validated_reopen;

include!("provider_recovery_full_audit_parts/fixture.rs");
include!("provider_recovery_full_audit_parts/online_fixture.rs");
include!("provider_recovery_full_audit_parts/terminal_fixture.rs");
include!("provider_recovery_full_audit_parts/part_01.rs");
include!("provider_recovery_full_audit_parts/part_02.rs");
include!("provider_recovery_full_audit_parts/part_03.rs");
include!("provider_recovery_full_audit_parts/part_04.rs");
include!("provider_recovery_full_audit_parts/part_05.rs");
include!("provider_recovery_full_audit_parts/part_06.rs");
include!("provider_recovery_full_audit_parts/part_07.rs");
include!("provider_recovery_full_audit_parts/part_08.rs");
include!("provider_recovery_full_audit_parts/part_09.rs");
include!("provider_recovery_full_audit_parts/part_10.rs");
include!("provider_recovery_full_audit_parts/part_11.rs");
include!("provider_recovery_full_audit_parts/part_12.rs");
include!("provider_recovery_full_audit_parts/part_13.rs");
