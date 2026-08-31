#![allow(dead_code)]

#[path = "support/online_proof.rs"]
mod online_proof;
#[path = "support/validated_reopen.rs"]
mod validated_reopen;

include!("provider_terminal_outbox/part_01.inc");
include!("provider_terminal_outbox/part_02.inc");
include!("provider_terminal_outbox/part_03.inc");
