#![allow(dead_code)]

#[path = "support/online_proof.rs"]
mod online_proof;
#[path = "support/validated_reopen.rs"]
mod validated_reopen;

include!("provider_execution_store/part_01.inc");
include!("provider_execution_store/part_02.inc");
