#[path = "../../runne-store/tests/support/online_credential_fixture.rs"]
mod online_credential_fixture;
#[path = "../../runne-store/tests/support/online_stream_fixture.rs"]
mod online_stream_fixture;
#[path = "support/v62_provider_terminal_upgrade.rs"]
mod v62_provider_terminal_upgrade;
#[path = "../../runne-store/tests/support/validated_reopen.rs"]
mod validated_reopen;

include!("provider_execution_recovery/part_01.inc");
include!("provider_execution_recovery/fixture.inc");
include!("provider_execution_recovery/part_02.inc");
include!("provider_execution_recovery/part_03.inc");
include!("provider_execution_recovery/part_04.inc");
include!("provider_execution_recovery/part_05.inc");
include!("provider_execution_recovery/part_06.inc");
include!("provider_execution_recovery/part_07.inc");
include!("provider_execution_recovery/part_08.inc");
include!("provider_execution_recovery/part_09.inc");
include!("provider_execution_recovery/part_10.inc");
include!("provider_execution_recovery/part_11.inc");
include!("provider_execution_recovery/part_12.inc");
include!("provider_execution_recovery/part_13.inc");
include!("provider_execution_recovery/part_14.inc");
include!("provider_execution_recovery/part_15.inc");
include!("provider_execution_recovery/part_16_unknown_terminal.inc");
include!("provider_execution_recovery/part_17_remote_recovery_forwarding.inc");

#[path = "../../runne-daemon/tests/support/nm10_rules.rs"]
mod nm10_rules;

include!("provider_execution_recovery/part_18_unknown_unpriced.inc");
include!("provider_execution_recovery/part_19_source1_matrix.inc");
include!("provider_execution_recovery/part_20_source1_late_heads.inc");
include!("provider_execution_recovery/part_21_source1_v62_upgrade.inc");
include!("provider_execution_recovery/part_22_source1_tamper.inc");
include!("provider_execution_recovery/part_23_source1_transplant.inc");
include!("provider_execution_recovery/part_24_d2_poll_bound.inc");
